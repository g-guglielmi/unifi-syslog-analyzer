#!/usr/bin/env python3
"""unifi-syslog-analyzer — entrypoint.

One process, three threads:
  * listener  — UDP syslog receiver aggregating flows into SQLite
  * refresher — periodic network/zone enumeration from the UniFi API
  * web       — dashboard + JSON API + CSV download

Configuration is environment variables only (docker-run friendly):

  DB_PATH               SQLite file            (default /data/flows.db)
  SYSLOG_PORT           UDP listen port        (default 5514)
  SYSLOG_BIND           UDP bind address       (default 0.0.0.0)
  HTTP_PORT             dashboard port         (default 8080)
  HTTP_BIND             dashboard bind address (default 0.0.0.0)
  UNPARSED_CAP          raw unparseable lines kept (default 10000)

  UNIFI_HOST            controller URL, e.g. https://192.168.1.1
  UNIFI_API_KEY         local API key (preferred; the only mode that works
                        when MFA is enforced on the console)
  UNIFI_USER            controller username (fallback, no-MFA accounts only)
  UNIFI_PASS            controller password
  UNIFI_SITE            site name              (default "default")
  UNIFI_VERIFY_SSL      "true" to verify TLS   (default false: self-signed)
  NETWORKS_REFRESH_MIN  enumeration interval   (default 60)

  NETWORKS_JSON         path to a static network table (JSON list of
                        {name, cidr, zone[, vlan_id, gateway_ip]}) — used
                        instead of / in addition to the UniFi API, e.g.
                        for non-UniFi firewalls.
"""

import json
import os
import signal
import sys
import threading

import listener
import store
import unifi_api
import webserver


def env(name, default=None):
    v = os.environ.get(name)
    return v if v not in (None, "") else default


def load_manual_networks(db, path):
    with open(path, "r", encoding="utf-8") as f:
        entries = json.load(f)
    rows = []
    for e in entries:
        rows.append({
            "key": "manual:" + e["name"],
            "name": e["name"],
            "vlan_id": e.get("vlan_id"),
            "cidr": e["cidr"],
            "gateway_ip": e.get("gateway_ip"),
            "zone": e.get("zone", "Internal"),
        })
    store.replace_networks(db, rows, "manual")
    print(f"[networks] loaded {len(rows)} manual networks from {path}")


def make_refresher(db_path, host, user, password, site, verify_ssl,
                   api_key=None):
    """Returns (refresh_once, loop) where refresh_once() -> result dict."""
    lock = threading.Lock()

    def refresh_once():
        with lock:
            client = unifi_api.UniFiClient(host, user, password, site,
                                           verify_ssl, api_key=api_key)
            rows, zone_source = unifi_api.fetch_network_rows(client)
            db = store.open_db(db_path)
            try:
                store.replace_networks(db, rows, "api")
                store.meta_set(db, "networks_source", zone_source)
                db.commit()
            finally:
                db.close()
            print(f"[networks] enumerated {len(rows)} networks "
                  f"from {host} (zone mapping: {zone_source})")
            sys.stdout.flush()
            return {"networks": len(rows), "zone_source": zone_source}

    def loop(stop_event, interval_min):
        while not stop_event.is_set():
            try:
                refresh_once()
            except Exception as e:
                print(f"[networks] refresh failed: {type(e).__name__}: {e} "
                      f"— keeping cached table", file=sys.stderr)
                sys.stderr.flush()
            stop_event.wait(interval_min * 60)

    return refresh_once, loop


def main():
    db_path = env("DB_PATH", "/data/flows.db")
    syslog_port = int(env("SYSLOG_PORT", "5514"))
    syslog_bind = env("SYSLOG_BIND", "0.0.0.0")
    http_port = int(env("HTTP_PORT", "8080"))
    http_bind = env("HTTP_BIND", "0.0.0.0")
    unparsed_cap = int(env("UNPARSED_CAP", "10000"))

    unifi_host = env("UNIFI_HOST")
    networks_json = env("NETWORKS_JSON")

    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    db = store.open_db(db_path)

    if networks_json:
        load_manual_networks(db, networks_json)

    refresh_once = None
    if unifi_host:
        refresh_once, refresh_loop = make_refresher(
            db_path, unifi_host, env("UNIFI_USER"), env("UNIFI_PASS"),
            env("UNIFI_SITE", "default"),
            env("UNIFI_VERIFY_SSL", "false").lower() == "true",
            api_key=env("UNIFI_API_KEY"))
    elif not networks_json:
        n = db.execute("SELECT COUNT(*) FROM networks").fetchone()[0]
        print("[networks] neither UNIFI_HOST nor NETWORKS_JSON configured"
              + (f" — using {n} cached networks" if n else
                 " and no cached table: all traffic will resolve to "
                 "External/Unknown until one is provided"),
              file=sys.stderr)
    db.close()

    stop_event = threading.Event()

    def on_signal(signum, frame):
        stop_event.set()
    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    if hasattr(signal, "SIGBREAK"):   # Windows console equivalent
        signal.signal(signal.SIGBREAK, on_signal)

    threads = []
    listener_thread = threading.Thread(
        target=listener.run, name="listener",
        args=(stop_event, db_path, syslog_port, syslog_bind, unparsed_cap))
    listener_thread.start()
    threads.append(listener_thread)

    if unifi_host:
        interval = int(env("NETWORKS_REFRESH_MIN", "60"))
        t = threading.Thread(target=refresh_loop, name="refresher",
                             args=(stop_event, interval), daemon=True)
        t.start()

    state = webserver.AppState(db_path, refresh_once)
    httpd = webserver.serve(state, http_bind, http_port)
    t = threading.Thread(target=httpd.serve_forever, name="web", daemon=True)
    t.start()

    listener_died = False
    while not stop_event.is_set():
        stop_event.wait(1.0)
        if not listener_thread.is_alive() and not stop_event.is_set():
            # The listener is the whole point; die loudly so the container
            # restart policy brings ingest back instead of a healthy-looking
            # shell that collects nothing.
            print("[main] listener thread died unexpectedly — exiting",
                  file=sys.stderr)
            listener_died = True
            stop_event.set()

    print("[main] shutting down...")
    httpd.shutdown()
    for t in threads:
        t.join(timeout=15)
    print("[main] bye")
    if listener_died:
        sys.exit(1)


if __name__ == "__main__":
    main()
