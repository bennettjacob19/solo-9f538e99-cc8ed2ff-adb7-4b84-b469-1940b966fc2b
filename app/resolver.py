"""Caching UDP DNS resolver for one fixed internal domain.

Behaviour (all timings from app.common, defaults are the spec values):

  * a successful A answer is cached fresh for FRESH_TTL (5s) and served from
    cache with the remaining TTL;
  * after expiry the resolver re-fetches.  If the upstream is unusable (times
    out, rejects the answer, or the answer's publish serial is lower than the
    one already accepted) the old A record may be served stale for at most
    STALE_WINDOW (20s) past expiry; beyond that the answer is SERVFAIL;
  * NXDOMAIN is cached fresh only -- it is never used as stale backup;
  * every answer carries a publish serial from the authoritative side.  The
    resolver durably remembers the highest serial it has accepted together
    with that serial's result (`replica_state`).  A lower serial, or the same
    serial carrying different content, is treated as "upstream unavailable"
    and never refreshes the cache.  Accepting a higher serial atomically
    replaces whatever was cached, so a newer A can replace a confirmed
    NXDOMAIN;
  * confirming NXDOMAIN purges the old A record durably (SQLite), so no later
    answer contains the old A again;
  * every upstream attempt uses a dedicated socket with a random transaction
    ID and matches the question section, so a late answer to an already
    timed-out query is never read and can never resurrect the old A;
  * cache deadlines are absolute epochs persisted in SQLite, so a restart does
    not extend the validity of an old A record, and the accepted serial is
    persisted separately so a restart cannot lower it.

The resolver reports where each answer came from in an additional-section TXT
record (_src.<domain> TXT "source=upstream|cache-fresh|cache-stale|none ...
serial=<n>") and logs every query to the query_log table for the web console.
"""
from __future__ import annotations

import random
import socket
import threading
import time
import traceback

from dnslib import A, CLASS, QTYPE, RCODE, RR, TXT, DNSHeader, DNSRecord

from . import common


def _same_name(a, b) -> bool:
    return str(a).rstrip(".").lower() == str(b).rstrip(".").lower()


def upstream_query() -> DNSRecord | None:
    """One-shot upstream A query for the fixed domain.

    A dedicated UDP socket per attempt plus a random transaction ID means a
    late answer to an earlier, already timed-out query can never be read back
    (the socket is closed) and can never be mistaken for the answer to a later
    query (ID + question must match).
    """
    query = DNSRecord.question(common.FQDN, "A")
    query.header.id = random.randint(0, 0xFFFF)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(query.pack(), (common.AUTH_HOST, common.AUTH_PORT))
        deadline = time.monotonic() + common.UPSTREAM_TIMEOUT
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            sock.settimeout(remaining)
            try:
                data, _addr = sock.recvfrom(4096)
            except socket.timeout:
                return None
            try:
                resp = DNSRecord.parse(data)
            except Exception:
                continue  # unparsable stray datagram: keep waiting
            if resp.header.id != query.header.id:
                continue  # stray/late packet for someone else: ignore
            if not _same_name(resp.q.qname, query.q.qname):
                continue
            return resp
    except OSError:
        return None
    finally:
        sock.close()


def _a_rr(ip: str, ttl: int) -> RR:
    return RR(common.FQDN, QTYPE.A, CLASS.IN, ttl, A(ip))


def _src_rr(source: str, detail: str, serial: int | None) -> RR:
    parts = [f"source={source}"]
    if serial is not None:
        parts.append(f"serial={int(serial)}")
    if detail:
        parts.append(detail)
    return RR(f"_src.{common.FQDN}", QTYPE.TXT, CLASS.IN, 0, TXT(" ".join(parts)))


def _reply(query: DNSRecord, rcode: int, answers=(), source="none",
           detail="", serial: int | None = None) -> DNSRecord:
    rep = DNSRecord(
        DNSHeader(
            id=query.header.id, qr=1, aa=0, ra=1, rd=query.header.rd, rcode=rcode
        ),
        q=query.q,
    )
    for rr in answers:
        rep.add_answer(rr)
    rep.add_ar(_src_rr(source, detail, serial))
    return rep


def _parse_upstream(resp: DNSRecord) -> tuple[int, str, str | None] | None:
    """Extract (serial, rcode, A) from an authoritative reply.

    Returns None when the reply is unusable: no publish serial, an rcode we do
    not cache, or NOERROR without an A record.
    """
    serial = None
    for rr in resp.ar:
        if rr.rtype != QTYPE.TXT or not _same_name(rr.rname, common.SERIAL_TXT_NAME):
            continue
        for token in str(rr.rdata).replace('"', "").split():
            if token.startswith("serial="):
                try:
                    serial = int(token.split("=", 1)[1])
                except ValueError:
                    serial = None
    if serial is None:
        return None
    if resp.header.rcode == RCODE.NOERROR:
        ips = [str(rr.rdata) for rr in resp.rr if rr.rtype == QTYPE.A]
        if not ips:
            return None
        return serial, "NOERROR", ips[0]
    if resp.header.rcode == RCODE.NXDOMAIN:
        return serial, "NXDOMAIN", None
    return None


def _serve_cache(query: DNSRecord, row: dict, source: str,
                 ms_left: float) -> tuple[DNSRecord, str, str]:
    fresh = source == "cache-fresh"
    if row["rcode"] == "NXDOMAIN":
        return (
            _reply(query, RCODE.NXDOMAIN, [], source,
                   f"{'fresh' if fresh else 'stale'}_left={ms_left:.1f}",
                   row["serial"]),
            source,
            f"{'fresh' if fresh else 'stale'} NXDOMAIN from cache"
            f" serial={row['serial']}",
        )
    ttl = max(1, int(ms_left + 0.999))
    return (
        _reply(query, RCODE.NOERROR, [_a_rr(row["a_record"], ttl)], source,
               f"{'fresh' if fresh else 'stale'}_left={ms_left:.1f}",
               row["serial"]),
        source,
        f"{'fresh' if fresh else 'stale'} A from cache serial={row['serial']}",
    )


def _serve_accepted(query: DNSRecord, outcome: dict, source: str,
                    now: float) -> tuple[DNSRecord, str, str] | None:
    """Serve the high-water result (with its serial) if the current cache row
    still matches it.  Returns None when the cache no longer holds that
    serial (a newer result was accepted meanwhile)."""
    if outcome["high_serial"] is None or outcome["high_rcode"] is None:
        return None
    row = common.get_cache()
    if not row or row["serial"] != outcome["high_serial"]:
        return None
    if now >= row["fresh_until"] and not (
        source == "cache-stale" and row["stale_until"] and now < row["stale_until"]
    ):
        return None
    return _serve_cache(query, row, source,
                        (row["fresh_until"] if source == "cache-fresh"
                         else row["stale_until"]) - now)


def resolve_a(query: DNSRecord) -> tuple[DNSRecord, str, str]:
    """Resolve the fixed domain's A record.  Returns (reply, source, detail)."""
    now = time.time()
    row = common.get_cache()

    # 1) fresh cache hits
    if row and row["rcode"] == "NOERROR" and row["a_record"] and now < row["fresh_until"]:
        return _serve_cache(query, row, "cache-fresh", row["fresh_until"] - now)
    if row and row["rcode"] == "NXDOMAIN" and now < row["fresh_until"]:
        return _serve_cache(query, row, "cache-fresh", row["fresh_until"] - now)

    # 2) expired: ask the authoritative endpoint
    resp = upstream_query()
    now2 = time.time()
    parsed = _parse_upstream(resp) if resp is not None else None

    if parsed is not None:
        serial, rcode, ip = parsed
        outcome = common.accept_upstream(serial, rcode, ip, now2)
        if outcome["accepted"]:
            if rcode == "NOERROR":
                return (
                    _reply(query, RCODE.NOERROR,
                           [_a_rr(ip, int(common.FRESH_TTL))], "upstream",
                           f"fetched serial={serial}", serial),
                    "upstream",
                    f"fetched A={ip} serial={serial} ({outcome['reason']})",
                )
            return (
                _reply(query, RCODE.NXDOMAIN, [], "upstream",
                       "nxdomain-confirmed", serial),
                "upstream",
                f"NXDOMAIN confirmed serial={serial}; old A purged",
            )

        reject = (f"serial={serial} {outcome['reason']}"
                  f" (accepted={outcome['high_serial']})")
        # A lower serial (or same serial, different content) must never
        # refresh the cache, and must never be what we answer with either:
        # if the high-water serial is still fresh, answer exactly that.
        fresh = _serve_accepted(query, outcome, "cache-fresh", now2)
        if fresh is not None:
            return fresh
    else:
        reject = "unusable reply" if resp is not None else "upstream timeout"

    # 3) upstream unusable / rejected: maybe serve the stale A record
    #    (NXDOMAIN is never served stale).  Only the high-water serial's A is
    #    ever eligible, and never below a higher serial already confirmed.
    if parsed is not None:
        stale = _serve_accepted(query, outcome, "cache-stale", now2)
        if stale is not None:
            return stale
    row = common.get_cache()
    if (
        row
        and row["rcode"] == "NOERROR"
        and row["a_record"]
        and row["stale_until"]
        and now2 < row["stale_until"]
    ):
        return _serve_cache(query, row, "cache-stale", row["stale_until"] - now2)

    return (
        _reply(query, RCODE.SERVFAIL, [], "none", reject, None),
        "none",
        f"{reject}; no usable cache",
    )


def handle_packet(data: bytes, addr, sock: socket.socket) -> None:
    qname = qtype = "?"
    try:
        query = DNSRecord.parse(data)
        qname = str(query.q.qname)
        qtype = QTYPE[query.q.qtype]
        if not _same_name(query.q.qname, common.FQDN):
            rep = _reply(query, RCODE.REFUSED, [], "none", "out-of-scope")
            source, detail = "none", "out-of-scope"
        elif query.q.qtype == QTYPE.A:
            rep, source, detail = resolve_a(query)
        else:
            rep = _reply(query, RCODE.NOERROR, [], "none", "nodata")
            source, detail = "none", "nodata"
        sock.sendto(rep.pack(), addr)
        answers = ";".join(
            f"{QTYPE[rr.rtype]}={rr.rdata}(ttl={rr.ttl})" for rr in rep.rr
        ) or "-"
        common.log_query(qname, qtype, source, RCODE[rep.header.rcode], answers, detail)
    except Exception:
        common.log_query(qname, qtype, "error", "SERVFAIL", "-",
                         traceback.format_exc(limit=3))


def main() -> None:
    common.init_db()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", common.RESOLVER_PORT))
    print(
        f"[resolver] {common.FQDN} on udp/{common.RESOLVER_PORT}, "
        f"upstream {common.AUTH_HOST}:{common.AUTH_PORT}, "
        f"fresh={common.FRESH_TTL}s stale={common.STALE_WINDOW}s "
        f"timeout={common.UPSTREAM_TIMEOUT}s",
        flush=True,
    )
    while True:
        data, addr = sock.recvfrom(4096)
        threading.Thread(target=handle_packet, args=(data, addr, sock),
                         daemon=True).start()


if __name__ == "__main__":
    main()
