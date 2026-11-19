#!/usr/bin/env python3
"""End-to-end self-test for the serve-stale DNS duty system.

Spawns auth + resolver + web on loopback with the production timing
parameters (fresh TTL 5s, stale window 20s, upstream timeout 2s) and drives
the key interleavings:

  A. basic fetch / fresh-cache hit / TTL countdown / refresh after expiry
  B. upstream timeout after expiry -> stale A (<=20s) -> SERVFAIL beyond
  C. confirmed NXDOMAIN purges the old A; NXDOMAIN is never served stale
  D. a late (delayed) old answer cannot resurrect anything
  E. resolver restart does not extend the old A's validity
  F. publish serials: lagging replicas, same-serial conflicts, a newer A
     replacing NXDOMAIN, concurrent out-of-order upstream answers, write
     failures, and a restart that must not lower the accepted serial
  G. web console smoke test (page, mode+serial switch, real UDP query)

Exits non-zero if any check fails.  Runtime: ~2.5 minutes.
"""
from __future__ import annotations

import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from dnslib import QTYPE, DNSRecord  # noqa: E402

DOMAIN = "service.example"
AUTH_PORT, RES_PORT, WEB_PORT = 15354, 15353, 18000
TMP = tempfile.mkdtemp(prefix="dns-selftest-")
DB = os.path.join(TMP, "app.db")

env = dict(os.environ)
env.update(
    DB_PATH=DB,
    FIXED_DOMAIN=DOMAIN,
    AUTH_HOST="127.0.0.1",
    AUTH_PORT=str(AUTH_PORT),
    RESOLVER_HOST="127.0.0.1",
    RESOLVER_PORT=str(RES_PORT),
    WEB_PORT=str(WEB_PORT),
    FRESH_TTL="5",
    STALE_WINDOW="20",
    UPSTREAM_TIMEOUT="2",
    DEFAULT_IP="192.0.2.10",
    DEFAULT_DELAY="3",
    PYTHONPATH=ROOT,
    PYTHONUNBUFFERED="1",
)

procs: dict[str, subprocess.Popen] = {}
FAILS: list[str] = []


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def start(name: str, module: str) -> None:
    log = open(os.path.join(TMP, f"{name}.log"), "ab")
    procs[name] = subprocess.Popen(
        [sys.executable, "-m", module],
        cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT,
    )


def stop(name: str) -> None:
    p = procs.get(name)
    if p and p.poll() is None:
        p.terminate()
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()


def db(timeout: float = 15.0) -> sqlite3.Connection:
    conn = sqlite3.connect(DB, timeout=timeout)
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout={int(timeout * 1000)}")
    return conn


def set_mode(mode: str, ip: str = "192.0.2.10", delay: float = 3.0,
             serial: int = 1) -> None:
    conn = db()
    conn.execute(
        "INSERT INTO control(id, mode, ip, delay_seconds, serial, updated_at)"
        " VALUES (1, ?, ?, ?, ?, ?)"
        " ON CONFLICT(id) DO UPDATE SET mode=excluded.mode, ip=excluded.ip,"
        " delay_seconds=excluded.delay_seconds, serial=excluded.serial,"
        " updated_at=excluded.updated_at",
        (mode, ip, delay, serial, time.time()),
    )
    conn.commit()
    conn.close()


def get_cache() -> dict | None:
    conn = db()
    row = conn.execute("SELECT * FROM cache WHERE id = 1").fetchone()
    conn.close()
    return dict(row) if row else None


def get_replica() -> dict | None:
    conn = db()
    row = conn.execute("SELECT * FROM replica_state WHERE id = 1").fetchone()
    conn.close()
    return dict(row) if row else None


def auth_actions() -> list[tuple]:
    conn = db()
    rows = conn.execute(
        "SELECT mode, action, detail FROM auth_log ORDER BY id"
    ).fetchall()
    conn.close()
    return rows


def clear_cache() -> None:
    conn = db()
    conn.execute("DELETE FROM cache WHERE id = 1")
    conn.commit()
    conn.close()


def dns_query(timeout: float = 8) -> tuple[int, list[tuple], str | None, int | None]:
    """Returns (rcode, [(type, data, ttl)], source, serial)."""
    q = DNSRecord.question(DOMAIN, "A")
    data = q.send("127.0.0.1", RES_PORT, timeout=timeout)
    rep = DNSRecord.parse(data)
    answers = [(QTYPE[rr.rtype], str(rr.rdata), rr.ttl) for rr in rep.rr]
    src = serial = None
    for rr in rep.ar:
        if rr.rtype != QTYPE.TXT:
            continue
        for token in str(rr.rdata).replace('"', "").split():
            if token.startswith("source="):
                src = token.split("=", 1)[1]
            elif token.startswith("serial="):
                serial = int(token.split("=", 1)[1])
    return rep.header.rcode, answers, src, serial


def check(name: str, cond: bool, info: str = "") -> None:
    print(f"  [{'PASS' if cond else 'FAIL'}] {name} {info}", flush=True)
    if not cond:
        FAILS.append(name)


def sleep_until(ts: float) -> None:
    time.sleep(max(0.0, ts - time.time()))


def wait_resolver_ready(timeout: float = 25) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            dns_query()
            return True
        except Exception:
            time.sleep(0.3)
    return False


def wait_web_ready(timeout: float = 25) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{WEB_PORT}/api/state", timeout=2
            ) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.3)
    return False


def db_write_locked(seconds: float) -> threading.Thread:
    """Hold SQLite's write lock in a background thread, to make the resolver's
    own write (cache + accepted serial) fail."""
    ready = threading.Event()

    def hold() -> None:
        conn = db()
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "UPDATE control SET updated_at = updated_at WHERE id = 1"
        )
        ready.set()
        time.sleep(seconds)
        conn.execute("ROLLBACK")
        conn.close()

    t = threading.Thread(target=hold, daemon=True)
    t.start()
    ready.wait(5)
    return t


# --------------------------------------------------------------------------
# scenario
# --------------------------------------------------------------------------
def main() -> int:
    print(f"[selftest] workdir={TMP}", flush=True)
    start("auth", "app.auth_server")
    start("resolver", "app.resolver")
    start("web", "app.web")
    try:
        if not (wait_resolver_ready() and wait_web_ready()):
            print("  [FAIL] services did not come up")
            return 1

        # -- A. basic fetch / fresh cache / refresh --------------------------
        print("A. 基本应答与新鲜缓存", flush=True)
        clear_cache()  # the readiness probe already populated the cache
        set_mode("a", "192.0.2.10", serial=1)
        rc, ans, src, ser = dns_query()
        check("A1 上游取回 A（带序号）",
              rc == 0 and ans == [("A", "192.0.2.10", 5)]
              and src == "upstream" and ser == 1, f"rcode={rc} ans={ans} src={src} serial={ser}")
        rc, ans, src, ser = dns_query()
        check("A2 命中新鲜缓存", rc == 0 and src == "cache-fresh" and ser == 1
              and ans and ans[0][1] == "192.0.2.10" and 1 <= ans[0][2] <= 5,
              f"ans={ans} src={src} serial={ser}")
        set_mode("a", "192.0.2.20", serial=2)  # republish a new A on the auth side
        rc, ans, src, ser = dns_query()
        check("A3 缓存期内仍给旧 IP/序号", rc == 0 and src == "cache-fresh" and ser == 1
              and ans and ans[0][1] == "192.0.2.10", f"ans={ans} src={src} serial={ser}")
        time.sleep(5.5)
        rc, ans, src, ser = dns_query()
        check("A4 过期后重新取回新 IP", rc == 0 and src == "upstream" and ser == 2
              and ans == [("A", "192.0.2.20", 5)], f"ans={ans} src={src} serial={ser}")
        cache = get_cache()
        fresh_until, stale_until = cache["fresh_until"], cache["stale_until"]

        # -- B. stale on timeout, SERVFAIL beyond the window -----------------
        print("B. 过期+上游超时 -> 旧 A 沿用 <=20s -> SERVFAIL", flush=True)
        set_mode("timeout")
        sleep_until(fresh_until + 0.5)
        t0 = time.time()
        rc, ans, src, ser = dns_query()
        check("B1 上游超时后给旧 A(stale)",
              rc == 0 and src == "cache-stale" and ser == 2 and ans
              and ans[0][1] == "192.0.2.20"
              and stale_until - time.time() - 1 <= ans[0][2] <= 20,
              f"ans={ans} src={src} 耗时={time.time()-t0:.1f}s")
        sleep_until(stale_until - 4)
        rc, ans, src, ser = dns_query()
        check("B2 窗口末尾仍是 stale", rc == 0 and src == "cache-stale",
              f"ans={ans} src={src}")
        sleep_until(stale_until + 1)
        rc, ans, src, ser = dns_query()
        check("B3 超过 20s 返回 SERVFAIL", rc == 2 and not ans and src == "none",
              f"rcode={rc} ans={ans} src={src}")

        # -- C. NXDOMAIN purges old A; NXDOMAIN never served stale -----------
        print("C. 确认 NXDOMAIN 清除旧 A；NXDOMAIN 不作过期备用", flush=True)
        set_mode("a", "192.0.2.30", serial=3)
        rc, ans, src, ser = dns_query()
        assert rc == 0 and src == "upstream" and ser == 3, f"setup failed: {rc} {src} {ser}"
        set_mode("nxdomain", serial=3)  # same serial, content changed -> rejected
        time.sleep(5.5)  # let the fresh A expire
        rc, ans, src, ser = dns_query()
        check("C0 同序号异内容按回源不可用处理（不刷新缓存）",
              rc == 0 and src == "cache-stale" and ser == 3 and ans
              and ans[0][1] == "192.0.2.30", f"rcode={rc} ans={ans} src={src}")
        set_mode("nxdomain", serial=4)
        rc, ans, src, ser = dns_query()
        check("C1 更高序号 NXDOMAIN 被接受", rc == 3 and not ans and src == "upstream"
              and ser == 4, f"rcode={rc} ans={ans} src={src} serial={ser}")
        cache = get_cache()
        check("C2 旧 A 已被持久清除",
              cache["rcode"] == "NXDOMAIN" and cache["a_record"] is None
              and cache["stale_until"] is None and cache["serial"] == 4,
              f"cache={cache}")
        set_mode("timeout")
        time.sleep(5.5)  # let the fresh NXDOMAIN expire
        rc, ans, src, ser = dns_query()
        check("C3 NXDOMAIN 不作 stale 备用 -> SERVFAIL",
              rc == 2 and not ans and src == "none",
              f"rcode={rc} ans={ans} src={src}")

        # -- D. late old answer cannot resurrect -----------------------------
        print("D. 超时后迟到的旧答复不能复活记录", flush=True)
        set_mode("a", "192.0.2.40", serial=5)
        rc, ans, src, ser = dns_query()
        assert rc == 0 and src == "upstream" and ser == 5, f"setup failed: {rc} {src} {ser}"
        set_mode("delay", "192.0.2.40", 3.0, serial=5)  # 3s delay > 2s upstream timeout
        time.sleep(5.5)  # fresh A expires
        t0 = time.time()
        rc, ans, src, ser = dns_query()  # upstream times out at 2s; delayed A lands ~1s later
        check("D1 延迟模式下先按超时处理 -> stale",
              rc == 0 and src == "cache-stale" and 1.8 <= time.time() - t0 <= 4,
              f"ans={ans} src={src} 耗时={time.time()-t0:.1f}s")
        time.sleep(1.5)  # the delayed A has now arrived at a closed socket
        set_mode("nxdomain", serial=6)
        rc, ans, src, ser = dns_query()
        check("D2 随后更高序号确认 NXDOMAIN", rc == 3 and src == "upstream" and ser == 6,
              f"rcode={rc} src={src} serial={ser}")
        set_mode("timeout")
        time.sleep(5.5)  # past NXDOMAIN freshness; delayed A long arrived
        rc, ans, src, ser = dns_query()
        check("D3 迟到旧 A 未复活任何记录 -> SERVFAIL",
              rc == 2 and not ans, f"rcode={rc} ans={ans} src={src}")
        cache = get_cache()
        check("D4 缓存中仍无 A 记录", cache["a_record"] is None,
              f"cache={cache}")
        delayed = [r for r in auth_actions() if r[0] == "delay" and r[1] == "answered"]
        check("D5 权威端确实发出过延迟应答（被解析器丢弃）", len(delayed) >= 1,
              f"delay 应答次数={len(delayed)}")

        # -- E. restart does not extend validity -----------------------------
        print("E. 重启不延长旧 A 有效期", flush=True)
        set_mode("a", "192.0.2.50", serial=7)
        rc, ans, src, ser = dns_query()
        assert rc == 0 and src == "upstream" and ser == 7, f"setup failed: {rc} {src} {ser}"
        stale_until = get_cache()["stale_until"]
        time.sleep(4)
        stop("resolver")
        time.sleep(1)
        start("resolver", "app.resolver")  # restart with the same DB
        set_mode("timeout")
        assert wait_resolver_ready(), "resolver did not come back"
        sleep_until(stale_until - 4)
        rc, ans, src, ser = dns_query()
        check("E1 重启后窗口内仍可用旧 A(绝对期限未变)",
              rc == 0 and src == "cache-stale" and ans
              and ans[0][1] == "192.0.2.50", f"ans={ans} src={src}")
        sleep_until(stale_until + 2)
        rc, ans, src, ser = dns_query()
        check("E2 到达原绝对期限即 SERVFAIL（未被重启延长）",
              rc == 2 and not ans, f"rcode={rc} ans={ans} src={src}")

        # -- F. publish serials ----------------------------------------------
        print("F. 发布序号：落后副本 / 同序号异内容 / 新 A 覆盖 NXDOMAIN / 乱序", flush=True)
        set_mode("a", "192.0.2.60", serial=10)
        rc, ans, src, ser = dns_query()
        assert rc == 0 and src == "upstream" and ser == 10, f"setup failed: {rc} {src} {ser}"
        # a lagging replica still publishing serial 9 with an old A
        set_mode("a", "192.0.2.61", serial=9)
        rc, ans, src, ser = dns_query()
        check("F1 新鲜期内不受落后副本影响", rc == 0 and src == "cache-fresh" and ser == 10,
              f"src={src} serial={ser}")
        time.sleep(5.5)  # expire
        rc, ans, src, ser = dns_query()
        check("F2 低序号不刷新缓存，也不得用低序号 A 作答",
              rc == 0 and src == "cache-stale" and ser == 10 and ans
              and ans[0][1] == "192.0.2.60", f"rcode={rc} ans={ans} src={src} serial={ser}")
        check("F3 已接受最高序号未被降低",
              (get_replica() or {}).get("serial") == 10, f"replica={get_replica()}")
        # the publisher re-releases the A at a higher serial
        set_mode("a", "192.0.2.62", serial=11)
        rc, ans, src, ser = dns_query()
        check("F4 更高序号重新发布的 A 被接受",
              rc == 0 and src == "upstream" and ser == 11
              and ans == [("A", "192.0.2.62", 5)], f"rcode={rc} ans={ans} serial={ser}")
        # NXDOMAIN at a higher serial only replaces NXDOMAIN itself
        set_mode("nxdomain", serial=12)
        time.sleep(5.5)
        rc, ans, src, ser = dns_query()
        assert rc == 3 and ser == 12, f"setup failed: {rc} {ser}"
        set_mode("a", "192.0.2.63", serial=13)
        time.sleep(5.5)  # the fresh NXDOMAIN must expire before re-fetching
        rc, ans, src, ser = dns_query()
        check("F5 更高序号的 A 替换已确认的 NXDOMAIN",
              rc == 0 and src == "upstream" and ser == 13
              and ans == [("A", "192.0.2.63", 5)], f"rcode={rc} ans={ans} serial={ser}")
        set_mode("nxdomain", serial=13)  # same serial, different content
        time.sleep(5.5)
        rc, ans, src, ser = dns_query()
        check("F6 同序号 NXDOMAIN 异内容被拒，仍给已接受 A",
              rc == 0 and src == "cache-stale" and ser == 13 and ans
              and ans[0][1] == "192.0.2.63", f"rcode={rc} ans={ans} src={src} serial={ser}")
        check("F7 冲突未改动缓存", get_cache()["serial"] == 13,
              f"cache={get_cache()}")
        # stale A finally expires; a lagging replica would still answer 11
        set_mode("a", "192.0.2.62", serial=11)
        sleep_until(get_cache()["stale_until"] + 1)
        rc, ans, src, ser = dns_query()
        check("F8 stale 窗口结束后低序号副本 -> SERVFAIL（不回退旧序号）",
              rc == 2 and not ans and src == "none", f"rcode={rc} ans={ans} src={src}")

        # -- concurrent out-of-order upstream answers ------------------------
        print("  并发回源乱序：低序号请求先发出、后完成", flush=True)
        set_mode("a", "192.0.2.70", serial=20)
        rc, ans, src, ser = dns_query()
        assert rc == 0 and ser == 20, f"setup failed: {rc} {ser}"
        time.sleep(5.5)  # expire so the next queries really go upstream
        results: dict[str, tuple] = {}

        def fire(tag: str) -> None:
            results[tag] = dns_query(timeout=15)

        # the lagging replica (serial 19) is slow: its answer will arrive after
        # the resolver has already confirmed serial 21 from the current one
        set_mode("delay", "192.0.2.69", 1.5, serial=19)
        t_low = threading.Thread(target=fire, args=("low",))
        t_low.start()
        time.sleep(0.3)
        set_mode("a", "192.0.2.71", 0.0, serial=21)
        time.sleep(0.3)
        t_high = threading.Thread(target=fire, args=("high",))
        t_high.start()
        t_high.join()
        check("F9 高序号答复先完成并写入",
              results["high"][3] == 21 and results["high"][0] == 0
              and get_cache()["serial"] == 21,
              f"high={results['high']} cache={get_cache()}")
        t_low.join()
        low = results["low"]
        check("F10 确认较高序号后发出的答复不含较低序号的 A",
              low[3] == 21 and low[0] == 0
              and not any(isinstance(a, tuple) and a[1] == "192.0.2.69"
                          for a in low[1])
              and any(isinstance(a, tuple) and a[1] == "192.0.2.71"
                      for a in low[1]),
              f"low={low}")
        before = get_cache()
        check("F11 最终缓存为最高序号的内容",
              before["serial"] == 21 and before["a_record"] == "192.0.2.71",
              f"cache={before}")

        # -- write failure: no half-new state --------------------------------
        print("  写入失败：不得留下半新半旧状态", flush=True)
        stop("resolver")
        env["DB_BUSY_TIMEOUT_MS"] = "600"  # make the resolver's own write fail fast
        start("resolver", "app.resolver")
        env["DB_BUSY_TIMEOUT_MS"] = "15000"
        assert wait_resolver_ready(30), "resolver did not come back"
        sleep_until(get_cache()["fresh_until"] + 0.3)
        before_cache = get_cache()
        before_replica = get_replica()
        set_mode("a", "192.0.2.80", serial=30)
        holder = db_write_locked(3.0)
        rc, ans, src, ser = dns_query(timeout=10)  # write fails -> cache untouched
        check("F12 写入失败后仍按回源不可用应答旧内容",
              rc == 0 and src == "cache-stale" and ser == before_cache["serial"]
              and ans and ans[0][1] == before_cache["a_record"],
              f"rcode={rc} ans={ans} src={src} serial={ser}")
        after_cache = get_cache()
        after_replica = get_replica()
        check("F13 写失败未留下半新半旧状态（缓存与已接受序号均未前进）",
              after_cache["serial"] == before_cache["serial"]
              and after_cache["a_record"] == before_cache["a_record"]
              and after_replica["serial"] == before_replica["serial"]
              and after_cache["serial"] == after_replica["serial"],
              f"before={before_cache} after={after_cache} replica={after_replica}")
        while holder.is_alive():
            time.sleep(0.2)
        time.sleep(0.3)
        # the write lock is gone: the serial-30 publisher is now accepted
        rc, ans, src, ser = dns_query()
        check("F14 写恢复后高序号正常被接受",
              rc == 0 and src == "upstream" and ser == 30
              and ans == [("A", "192.0.2.80", 5)],
              f"rcode={rc} ans={ans} src={src} serial={ser}")

        # -- restart must not lower the accepted serial ----------------------
        print("  重启不得降低已接受序号", flush=True)
        high_before = get_replica()["serial"]
        stop("resolver")
        time.sleep(1)
        start("resolver", "app.resolver")
        assert wait_resolver_ready(), "resolver did not come back"
        check("F15 重启后已接受序号不变",
              (get_replica() or {}).get("serial") == high_before,
              f"before={high_before} after={get_replica()}")
        set_mode("a", "192.0.2.81", serial=high_before - 1)
        # force a re-fetch: expire the cache row (deadlines are absolute)
        conn = db()
        conn.execute("UPDATE cache SET fresh_until = ?, stale_until = ? WHERE id = 1",
                     (time.time() - 1, time.time() - 1))
        conn.commit()
        conn.close()
        rc, ans, src, ser = dns_query()
        check("F16 重启后低序号仍被拒（SERVFAIL，不回退）",
              rc == 2 and not ans, f"rcode={rc} ans={ans} src={src}")

        # -- G. web console smoke test ---------------------------------------
        print("G. 网页控制台冒烟", flush=True)
        with urllib.request.urlopen(f"http://127.0.0.1:{WEB_PORT}/", timeout=5) as r:
            body = r.read().decode()
        check("G1 主页可访问", r.status == 200 and "DNS" in body)
        req = urllib.request.Request(
            f"http://127.0.0.1:{WEB_PORT}/api/mode",
            data=json.dumps({"mode": "a", "ip": "192.0.2.90", "serial": 40}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=5) as r:
            ok = json.load(r)["ok"]
        check("G2 网页切换到新序号+新地址", ok and get_control_mode() == "a"
              and control_serial() == 40)
        conn = db()
        conn.execute("UPDATE cache SET fresh_until = ?, stale_until = ? WHERE id = 1",
                     (time.time() - 1, time.time() - 1))
        conn.commit()
        conn.close()
        req = urllib.request.Request(f"http://127.0.0.1:{WEB_PORT}/api/query",
                                     method="POST")
        with urllib.request.urlopen(req, timeout=15) as r:
            res = json.load(r)
        check("G3 网页发起真实 UDP 查询并显示来源与序号",
              res["ok"] and res["rcode"] == "NOERROR"
              and res["source"] in ("upstream", "cache-fresh")
              and res["serial"] == 40
              and res["answers"] and res["answers"][0]["data"] == "192.0.2.90",
              f"res={res.get('rcode')} src={res.get('source')} serial={res.get('serial')}")
        with urllib.request.urlopen(
                f"http://127.0.0.1:{WEB_PORT}/api/state", timeout=5) as r:
            st = json.load(r)
        check("G4 状态接口含控制/缓存/已接受序号/日志",
              st["control"]["mode"] == "a" and st["control"]["serial"] == 40
              and st["cache"]["serial"] == 40 and st["replica"]["serial"] == 40
              and len(st["resolver_log"]) > 0 and len(st["auth_log"]) > 0)
        req = urllib.request.Request(
            f"http://127.0.0.1:{WEB_PORT}/api/mode",
            data=json.dumps({"mode": "bogus"}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            urllib.request.urlopen(req, timeout=5)
            check("G5 非法模式被拒绝", False)
        except urllib.error.HTTPError as e:
            check("G5 非法模式被拒绝", e.code == 400)
    finally:
        for name in list(procs):
            stop(name)
        print(f"[selftest] logs in {TMP}", flush=True)

    print(f"\n{'=' * 60}\n结果: {len(FAILS)} 项失败" if FAILS
          else f"\n{'=' * 60}\n结果: 全部通过", flush=True)
    return 1 if FAILS else 0


def get_control_mode() -> str:
    conn = db()
    mode = conn.execute("SELECT mode FROM control WHERE id = 1").fetchone()[0]
    conn.close()
    return mode


def control_serial() -> int:
    conn = db()
    serial = conn.execute("SELECT serial FROM control WHERE id = 1").fetchone()[0]
    conn.close()
    return serial


if __name__ == "__main__":
    sys.exit(main())
