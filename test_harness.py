#!/usr/bin/env python3
"""End-to-end synthetic test for unifi-syslog-analyzer.

Spawns the real app (app/main.py) with a throwaway database and a static
network table, feeds it synthetic UniFi-style syslog over UDP, and
asserts on the HTTP API, the CSV export, and the SQLite contents —
including the SIGTERM-mid-batch case (container stop must lose nothing).

Run it in the image (or any host with Python 3 — Windows included, where
the graceful-stop signal is CTRL_BREAK instead of SIGTERM):

    docker run --rm unifi-syslog-analyzer python3 /app/test_harness.py

Exit code 0 = all checks pass.  No network access needed beyond loopback.
"""

import json
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

IS_WIN = os.name == "nt"

HERE = os.path.dirname(os.path.abspath(__file__))
MAIN = os.path.join(HERE, "app", "main.py")
if not os.path.exists(MAIN):          # installed layout: /app/main.py
    MAIN = os.path.join(HERE, "main.py")

UDP_PORT = 15514
HTTP_PORT = 18080
BASE = f"http://127.0.0.1:{HTTP_PORT}"

TEST_NETWORKS = [
    {"name": "Telefoni", "vlan_id": 30, "cidr": "10.0.30.0/24", "zone": "Internal"},
    {"name": "Server",   "vlan_id": 20, "cidr": "10.0.20.0/24", "zone": "Internal"},
    {"name": "PC",       "vlan_id": 40, "cidr": "10.0.40.0/24", "zone": "Internal",
     "gateway_ip": "10.0.40.1"},
    {"name": "DMZ",      "vlan_id": 50, "cidr": "172.16.50.0/24", "zone": "DMZ"},
    {"name": "Guest",    "vlan_id": 200, "cidr": "10.31.0.0/16", "zone": "Guest"},
    {"name": "MPLS",     "vlan_id": 2020, "cidr": "10.20.20.0/24", "zone": "MPLS"},
]

checks = {"pass": 0, "fail": 0}


def check(name, cond, detail=""):
    if cond:
        checks["pass"] += 1
        print(f"  PASS  {name}")
    else:
        checks["fail"] += 1
        print(f"  FAIL  {name}  {detail}")


def get_json(path):
    with urllib.request.urlopen(BASE + path, timeout=10) as r:
        return json.loads(r.read())


def line(tag, descr, src, dst, proto, spt=None, dpt=None):
    parts = ["<4>Jul 16 12:00:00 UDM-Pro-Max kernel:"]
    if tag:
        parts.append(f"[{tag}]")
    if descr is not None:
        parts.append(f'DESCR="{descr}"')
    parts.append(f"IN=br0 OUT=br1 MAC=aa:bb:cc SRC={src} DST={dst} "
                 f"LEN=100 TOS=0x00 TTL=63 ID=0 DF PROTO={proto}")
    if spt is not None:
        parts.append(f"SPT={spt}")
    if dpt is not None:
        parts.append(f"DPT={dpt}")
    return " ".join(parts).encode()


def read_stdout(proc, lines):
    for l in proc.stdout:
        lines.append(l.rstrip("\n"))


def main():
    tmp = tempfile.mkdtemp(prefix="usa-test-")
    db_path = os.path.join(tmp, "flows.db")
    net_json = os.path.join(tmp, "networks.json")
    with open(net_json, "w") as f:
        json.dump(TEST_NETWORKS, f)

    env = dict(os.environ,
               DB_PATH=db_path,
               SYSLOG_PORT=str(UDP_PORT), SYSLOG_BIND="127.0.0.1",
               HTTP_PORT=str(HTTP_PORT), HTTP_BIND="127.0.0.1",
               NETWORKS_JSON=net_json)
    env.pop("UNIFI_HOST", None)

    print("== startup ==")
    # On Windows the graceful-stop signal is CTRL_BREAK (SIGBREAK), which
    # needs the child in its own process group; on POSIX it's SIGTERM.
    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if IS_WIN else 0
    proc = subprocess.Popen([sys.executable, "-u", MAIN],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, env=env, creationflags=creationflags)
    out_lines = []
    threading.Thread(target=read_stdout, args=(proc, out_lines),
                     daemon=True).start()

    up = False
    deadline = time.time() + 15
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        try:
            get_json("/api/summary")
            up = True
            break
        except (urllib.error.URLError, ConnectionError, OSError):
            time.sleep(0.3)
    check("app started, http answering", up, "\n".join(out_lines[:10]))
    if not up:
        proc.kill()
        sys.exit(1)

    nets = get_json("/api/networks")
    check("6 networks loaded from NETWORKS_JSON", len(nets) == 6,
          f"got {len(nets)}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send = lambda pkt: sock.sendto(pkt, ("127.0.0.1", UDP_PORT))
    pace = lambda: time.sleep(0.05)

    print("== synthetic traffic ==")
    for _ in range(20):   # SIP: Telefoni -> DMZ
        send(line("LAN_IN-A-2001", "Allow Telefoni to DMZ SIP",
                  "10.0.30.15", "172.16.50.10", "UDP", 5060, 5060))
    pace()
    for p in range(10000, 10051):   # RTP range, must consolidate
        send(line("LAN_IN-A-2001", "Allow Telefoni to DMZ SIP",
                  "10.0.30.15", "172.16.50.10", "UDP", 4000, p))
    pace()
    for _ in range(50):   # DNS: PC -> Server (10 more later, pre-SIGTERM)
        send(line("LAN_IN-A-2002", "Allow PC DNS",
                  "10.0.40.50", "10.0.20.5", "UDP", 40000, 53))
    pace()
    for _ in range(30):   # HTTPS: PC -> internet
        send(line("LAN_IN-A-2003", "Allow PC web",
                  "10.0.40.51", "93.184.216.34", "TCP", 40001, 443))
    pace()
    for _ in range(10):   # SMB allowed: PC -> Server
        send(line("LAN_IN-A-2004", "Allow PC to Server SMB",
                  "10.0.40.50", "10.0.20.5", "TCP", 40002, 445))
    for _ in range(5):    # SMB blocked from Guest: action from -D- tag
        send(line("GUEST_IN-D-4001", "Guest isolation",
                  "10.31.0.77", "10.0.20.5", "TCP", 40003, 445))
    for _ in range(5):    # ICMP: no DPT -> -1 sentinel
        send(line("LAN_IN-A-2005", "Allow ping",
                  "10.0.40.50", "10.0.20.5", "ICMP"))
    pace()
    # Port scan: internet -> DMZ (source must be genuinely global —
    # ipaddress treats documentation ranges as non-global).
    for p in range(1, 151):
        send(line("WAN_IN-D-3001", "Drop WAN to DMZ",
                  "8.8.4.4", "172.16.50.10", "TCP", 55555, p))
        if p % 50 == 0:
            pace()
    pace()
    for _ in range(5):    # keyword fallback: no tag, action from DESCR
        send(line(None, "allow mpls apps",
                  "10.20.20.30", "10.0.20.5", "TCP", 40004, 8080))
    send(b"totally not a syslog line")
    send(b"<4>kernel: SRC=only-half a line with no DST field PROTO=")
    send(b"\xff\xfe garbage \x00 bytes")

    print("   waiting past a flush interval (7 s)...")
    time.sleep(7)

    print("== api assertions ==")
    rep = get_json("/api/report")
    rows = {(r["src_zone"], r["dst_zone"], r["proto"], r["action"]): r
            for r in rep["rows"]}

    x = rows.get(("Internal", "DMZ", "UDP", "Allow"))
    check("SIP+RTP group exists", x is not None)
    if x:
        check("RTP consolidated to 10000-10050", "10000-10050" in x["ports"],
              x["ports"])
        check("52 distinct ports", x["distinct_ports"] == 52,
              str(x["distinct_ports"]))
        check("rule candidate flag", x["rule_candidate"] is True)
        check("hits = 71", x["hits"] == 71, str(x["hits"]))

    x = rows.get(("External", "DMZ", "TCP", "Drop"))
    check("scan flagged, not a candidate",
          x is not None and x["scan_flag"] and not x["rule_candidate"]
          and "probable scan" in x["ports"], str(x))

    x = rows.get(("Guest", "Internal", "TCP", "Drop"))
    check("guest SMB drop: tag -D- -> Drop, 5 hits on 445",
          x is not None and x["hits"] == 5 and x["ports"] == "445", str(x))

    x = rows.get(("Internal", "Internal", "ICMP", "Allow"))
    check("ICMP group shows no-port marker",
          x is not None and "no port" in x["ports"], str(x))

    x = rows.get(("MPLS", "Internal", "TCP", "Allow"))
    check("keyword-fallback action group exists", x is not None)

    x = rows.get(("Internal", "External", "TCP", "Allow"))
    check("HTTPS group: 30 hits", x is not None and x["hits"] == 30, str(x))

    summary = get_json("/api/summary")
    check("summary: 326 parsed", summary["parsed"] == 326,
          str(summary["parsed"]))
    check("summary: 3 unparseable", summary["unparseable"] == 3,
          str(summary["unparseable"]))

    unp = get_json("/api/unparsed?limit=10")
    check("unparsed raw lines retrievable", len(unp) == 3 and
          any("totally not" in r["raw"] for r in unp), str(len(unp)))

    with urllib.request.urlopen(BASE + "/api/report.csv", timeout=10) as r:
        csv_text = r.read().decode()
        disp = r.headers.get("Content-Disposition", "")
    check("csv: attachment with consolidated ports",
          "attachment" in disp and "10000-10050" in csv_text
          and csv_text.startswith("src_zone,"), disp)

    try:
        urllib.request.urlopen(
            urllib.request.Request(BASE + "/api/refresh-networks",
                                   data=b"", method="POST"), timeout=10)
        refreshed_code = 200
    except urllib.error.HTTPError as e:
        refreshed_code = e.code
    check("refresh-networks returns 400 without UNIFI_HOST",
          refreshed_code == 400, str(refreshed_code))

    print("== live log ==")
    live = get_json("/api/live?since=0&limit=2000")
    check("live: seq == 326 parsed events", live["seq"] == 326,
          str(live["seq"]))
    check("live: all events buffered", len(live["events"]) == 326,
          str(len(live["events"])))
    ev = live["events"][0]
    check("live: event fields present",
          all(k in ev for k in ("seq", "ts", "src", "dst", "proto",
                                "dst_port", "action", "descr")), str(ev))
    check("live: has Drop events with ports",
          any(e["action"] == "Drop" and e["dst_port"] == 445
              for e in live["events"]))
    check("live: ICMP event carries -1 port sentinel",
          any(e["proto"] == "ICMP" and e["dst_port"] == -1
              for e in live["events"]))
    tail = get_json(f"/api/live?since={live['seq']}")
    check("live: incremental fetch returns nothing new",
          tail["seq"] == live["seq"] and tail["events"] == [], str(tail))

    print("== SIGTERM mid-batch (container stop case) ==")
    for _ in range(10):   # DNS total must reach 60 only via final flush
        send(line("LAN_IN-A-2002", "Allow PC DNS",
                  "10.0.40.50", "10.0.20.5", "UDP", 40000, 53))
    for _ in range(10):   # to the PC gateway IP -> zone Gateway
        send(line("LAN_IN-A-2006", "Allow PC DNS to gateway",
                  "10.0.40.50", "10.0.40.1", "UDP", 40000, 53))
    time.sleep(0.5)       # well inside the 5 s flush window
    proc.send_signal(signal.CTRL_BREAK_EVENT if IS_WIN else signal.SIGTERM)
    try:
        rc = proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()
        rc = None
    time.sleep(0.5)
    check("clean exit on graceful-stop signal", rc == 0, f"rc={rc}")
    check("final flush logged", any("final flush" in l for l in out_lines),
          "\n".join(out_lines[-6:]))

    print("== database assertions ==")
    db = sqlite3.connect(db_path)
    r = db.execute("SELECT hits FROM flows WHERE src_ip='10.0.40.50' AND "
                   "dst_ip='10.0.20.5' AND proto='UDP' AND dst_port=53"
                   ).fetchone()
    check("DNS aggregated to 60 incl. post-flush batch",
          r is not None and r[0] == 60, f"row={r}")
    r = db.execute("SELECT hits FROM flows WHERE dst_ip='10.0.40.1'"
                   ).fetchone()
    check("gateway-bound rows survived SIGTERM flush",
          r is not None and r[0] == 10, f"row={r}")
    db.close()

    print(f"\n{checks['pass']} passed, {checks['fail']} failed. "
          f"(artifacts in {tmp})")
    sys.exit(1 if checks["fail"] else 0)


if __name__ == "__main__":
    main()
