"""Local authoritative endpoint for the fixed domain (simulated replica).

Its behaviour is switched at runtime from the web console via the shared
control table (read on every query, so changes take effect immediately):

  a        -- answer the configured A record (TTL = FRESH_TTL)
  nxdomain -- answer NXDOMAIN
  delay    -- answer the A record only after `delay_seconds` (longer than the
              resolver's upstream timeout, to exercise late-answer handling)
  timeout  -- never answer (simulates the authoritative endpoint being lost)

Every answer carries the configured publish sequence number in an
additional-section record, `_serial.<domain> TXT "serial=<n>"`, so the resolver
can order responses from replicas that may be lagging behind.  The sequence is
snapshotted together with mode/ip when the query arrives, so a delayed answer
still carries the serial that was current when it was produced.

Every received query is logged to auth_log so the console can show what the
upstream actually saw and did.
"""
from __future__ import annotations

import socket
import threading
import time
import traceback

from dnslib import A, CLASS, QTYPE, RCODE, RR, TXT, DNSRecord

from . import common


def _serial_rr(serial: int) -> RR:
    return RR(common.SERIAL_TXT_NAME, QTYPE.TXT, CLASS.IN, 0,
              TXT(f"serial={int(serial)}"))


def handle(data: bytes, addr, sock: socket.socket) -> None:
    qname = qtype = "?"
    mode = "?"
    try:
        query = DNSRecord.parse(data)
        qname = str(query.q.qname)
        qtype = QTYPE[query.q.qtype]
        ctl = common.get_control() or {
            "mode": "a", "ip": common.DEFAULT_IP,
            "delay_seconds": common.DEFAULT_DELAY,
            "serial": common.DEFAULT_SERIAL,
        }
        mode = ctl["mode"]
        serial = int(ctl["serial"])

        in_scope = (
            str(query.q.qname).rstrip(".").lower() == common.FIXED_DOMAIN.lower()
            and query.q.qtype in (QTYPE.A, QTYPE.ANY)
        )
        if not in_scope:
            rep = query.reply()
            rep.header.rcode = RCODE.NXDOMAIN
            sock.sendto(rep.pack(), addr)
            common.log_auth(qname, qtype, mode, "nxdomain", "out-of-scope name/qtype")
            return

        if mode == "timeout":
            common.log_auth(qname, qtype, mode, "dropped",
                            "simulating lost authoritative endpoint")
            return  # no answer at all -> the resolver's upstream times out

        if mode == "delay":
            time.sleep(max(0.0, float(ctl["delay_seconds"])))

        if mode == "nxdomain":
            rep = query.reply()
            rep.header.rcode = RCODE.NXDOMAIN
            rep.add_ar(_serial_rr(serial))
            sock.sendto(rep.pack(), addr)
            common.log_auth(qname, qtype, mode, "nxdomain",
                            f"confirmed negative serial={serial}")
            return

        # modes "a" and "delay": answer the configured A record
        rep = query.reply()
        rep.add_answer(
            RR(common.FQDN, QTYPE.A, rdata=A(ctl["ip"]), ttl=int(common.FRESH_TTL))
        )
        rep.add_ar(_serial_rr(serial))
        sock.sendto(rep.pack(), addr)
        suffix = (f" after {ctl['delay_seconds']}s delay" if mode == "delay" else "")
        common.log_auth(qname, qtype, mode, "answered",
                        f"A={ctl['ip']} serial={serial}{suffix}")
    except Exception:
        common.log_auth(qname, qtype, mode, "error", traceback.format_exc(limit=3))


def main() -> None:
    common.init_db()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", common.AUTH_PORT))
    print(f"[auth] authoritative for {common.FQDN} on udp/{common.AUTH_PORT}",
          flush=True)
    while True:
        data, addr = sock.recvfrom(4096)
        threading.Thread(target=handle, args=(data, addr, sock), daemon=True).start()


if __name__ == "__main__":
    main()
