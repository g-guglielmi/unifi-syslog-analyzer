"""UDP syslog listener thread.

Aggregates at ingest: one row per unique (src, dst, proto, dst_port,
descr) with a hit counter and first/last-seen, flushed to SQLite every
FLUSH_INTERVAL seconds, so the database stays small regardless of capture
duration.  Unparseable lines are kept raw (capped) for diagnosis.
The thread owns its own SQLite connection and performs a final flush when
the stop event is set — a container SIGTERM loses nothing.
"""

import socket
import sys
import time

import parser
import store

FLUSH_INTERVAL = 5.0
STATS_INTERVAL = 60.0
RECVBUF_REQUEST = 8 * 1024 * 1024


def _flush(db, pending, unparsed_rows, counters):
    if pending:
        db.executemany(store.UPSERT_FLOW, [
            (src, dst, proto, dport, descr, v[3], v[0], v[1], v[2])
            for (src, dst, proto, dport, descr), v in pending.items()
        ])
        pending.clear()
    if unparsed_rows:
        db.executemany(
            "INSERT INTO unparsed (received_at, raw) VALUES (?,?)",
            unparsed_rows)
        unparsed_rows.clear()
    for key, val in counters.items():
        store.meta_set(db, "stat_" + key, val)
    db.commit()


def run(stop_event, db_path, port, bind="0.0.0.0", unparsed_cap=10000):
    db = store.open_db(db_path)

    counters = {
        "received": int(store.meta_get(db, "stat_received", "0")),
        "parsed": int(store.meta_get(db, "stat_parsed", "0")),
        "unparseable": int(store.meta_get(db, "stat_unparseable", "0")),
    }
    unparsed_stored = db.execute("SELECT COUNT(*) FROM unparsed").fetchone()[0]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RECVBUF_REQUEST)
    granted = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
    sock.bind((bind, port))
    sock.settimeout(1.0)

    print(f"[listener] udp://{bind}:{port} -> {db_path}")
    print(f"[listener] rcvbuf: requested {RECVBUF_REQUEST // 1024} KB, "
          f"granted {granted // 1024} KB (Linux reports 2x the set value; "
          f"if well below 4096 KB raise net.core.rmem_max)")
    sys.stdout.flush()

    pending = {}        # key -> [hits, first_seen, last_seen, action]
    unparsed_rows = []  # (received_at, raw)
    last_flush = last_stats = time.monotonic()

    while not stop_event.is_set():
        try:
            data, _addr = sock.recvfrom(65535)
        except socket.timeout:
            data = None
        except OSError:
            if stop_event.is_set():
                break
            raise

        if data is not None:
            counters["received"] += 1
            text = data.decode("utf-8", "replace")
            rec = parser.parse_line(text)
            now = int(time.time())
            if rec is None:
                counters["unparseable"] += 1
                if unparsed_stored + len(unparsed_rows) < unparsed_cap:
                    unparsed_rows.append((now, text))
            else:
                counters["parsed"] += 1
                src, dst, proto, dport, descr, action = rec
                key = (src, dst, proto, dport, descr)
                v = pending.get(key)
                if v is None:
                    pending[key] = [1, now, now, action]
                else:
                    v[0] += 1
                    v[2] = now
                    v[3] = action

        mono = time.monotonic()
        if mono - last_flush >= FLUSH_INTERVAL:
            unparsed_stored += len(unparsed_rows)
            _flush(db, pending, unparsed_rows, counters)
            last_flush = mono
        if mono - last_stats >= STATS_INTERVAL:
            print(f"[listener] received={counters['received']} "
                  f"parsed={counters['parsed']} "
                  f"unparseable={counters['unparseable']} "
                  f"pending={len(pending)}")
            sys.stdout.flush()
            last_stats = mono

    # Final flush — the SIGTERM / container-stop safety net.
    unparsed_stored += len(unparsed_rows)
    _flush(db, pending, unparsed_rows, counters)
    db.close()
    sock.close()
    print(f"[listener] stopped cleanly; received={counters['received']}, "
          f"final flush done")
    sys.stdout.flush()
