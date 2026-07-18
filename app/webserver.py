"""HTTP server: dashboard page + JSON API + CSV download.

Read-only against the database (the listener thread is the sole writer).
A single lock serializes report building; this is an operator dashboard,
not a public site — see the README's security notes.
"""

import json
import os
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import report as report_mod
import store
from resolver import Resolver

_STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "static")


class AppState:
    """Shared, lock-guarded access to the db for HTTP handlers."""

    def __init__(self, db_path, refresh_networks_cb=None):
        self.db_path = db_path
        self.refresh_networks_cb = refresh_networks_cb
        self.lock = threading.Lock()
        self._db = None
        self._resolver = None

    def _ensure(self):
        if self._db is None:
            # read-only: the listener thread is the writer; this connection
            # only serves reports and queries (main.py created the file).
            self._db = store.open_db(self.db_path, read_only=True)
            self._resolver = Resolver(self._db)

    def build_report(self):
        with self.lock:
            self._ensure()
            return report_mod.build(self._db, self._resolver)

    def query(self, fn):
        with self.lock:
            self._ensure()
            return fn(self._db)


def _summary(db):
    row = db.execute("SELECT COUNT(*), COALESCE(SUM(hits),0), "
                     "MIN(first_seen), MAX(last_seen) FROM flows").fetchone()
    n_networks = db.execute("SELECT COUNT(*) FROM networks").fetchone()[0]
    n_unparsed = db.execute("SELECT COUNT(*) FROM unparsed").fetchone()[0]
    zones = [r[0] for r in db.execute(
        "SELECT DISTINCT zone FROM networks ORDER BY zone")]
    return {
        "flow_rows": row[0],
        "events": int(row[1]),
        "capture_start": row[2],
        "capture_end": row[3],
        "networks": n_networks,
        "zones": zones,
        "unparsed": n_unparsed,
        "received": int(store.meta_get(db, "stat_received", "0")),
        "parsed": int(store.meta_get(db, "stat_parsed", "0")),
        "unparseable": int(store.meta_get(db, "stat_unparseable", "0")),
        "networks_refreshed_api": store.meta_get(
            db, "networks_refreshed_api"),
        "networks_source_detail": store.meta_get(db, "networks_source"),
        "now": int(time.time()),
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "unifi-syslog-analyzer"
    state = None  # injected

    def log_message(self, fmt, *args):
        pass  # keep container logs for the listener's signal, not per-GET noise

    def _send(self, code, body, ctype="application/json; charset=utf-8",
              extra_headers=None):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj))

    def do_GET(self):
        path, _, query = self.path.partition("?")
        params = urllib.parse.parse_qs(query)
        try:
            if path in ("/", "/index.html"):
                with open(os.path.join(_STATIC_DIR, "index.html"), "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            elif path == "/api/summary":
                self._json(self.state.query(_summary))
            elif path == "/api/report":
                self._json(self.state.build_report())
            elif path == "/api/report.csv":
                csv_text = report_mod.to_csv(self.state.build_report())
                fname = time.strftime("zone-traffic-%Y%m%d-%H%M.csv")
                self._send(200, csv_text, "text/csv; charset=utf-8",
                           {"Content-Disposition":
                            f'attachment; filename="{fname}"'})
            elif path == "/api/networks":
                self._json(self.state.query(store.load_networks))
            elif path == "/api/unparsed":
                try:
                    limit = min(int(params.get("limit", ["25"])[0]), 500)
                except ValueError:
                    self._json({"error": "limit must be an integer"}, 400)
                    return
                rows = self.state.query(lambda db: [
                    {"received_at": r[0], "raw": r[1]} for r in db.execute(
                        "SELECT received_at, raw FROM unparsed "
                        "ORDER BY id DESC LIMIT ?", (limit,))])
                self._json(rows)
            else:
                self._json({"error": "not found"}, 404)
        except BrokenPipeError:
            pass
        except Exception as e:
            try:
                self._json({"error": f"{type(e).__name__}: {e}"}, 500)
            except Exception:
                pass

    def do_POST(self):
        if self.path == "/api/refresh-networks":
            cb = self.state.refresh_networks_cb
            if cb is None:
                self._json({"error": "no UniFi controller configured "
                            "(UNIFI_HOST unset)"}, 400)
                return
            try:
                result = cb()
                self._json({"ok": True, **result})
            except Exception as e:
                self._json({"error": f"{type(e).__name__}: {e}"}, 502)
        else:
            self._json({"error": "not found"}, 404)


def serve(state, bind, port):
    Handler.state = state
    httpd = ThreadingHTTPServer((bind, port), Handler)
    httpd.daemon_threads = True
    print(f"[web] dashboard on http://{bind}:{port}")
    return httpd
