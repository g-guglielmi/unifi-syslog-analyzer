"""Zone-pair report built from the flows table.

Groups by (src_zone, dst_zone, proto, action); consolidates destination
ports into consecutive ranges; flags groups with >100 distinct ports as
probable scans (not rule candidates); records which existing firewall
rules the traffic matched so already-covered traffic is distinguishable
from catch-all traffic.
"""

import csv
import io
import time

MAX_RANGES_SHOWN = 15
SCAN_THRESHOLD = 100
MAX_RULE_NAMES = 5

CSV_FIELDS = ["src_zone", "dst_zone", "proto", "action", "hits",
              "distinct_src_ips", "distinct_dst_ips", "distinct_ports",
              "ports", "rule_candidate", "scan_flag", "rules_matched",
              "first_seen", "last_seen"]

ACTION_ORDER = {"Allow": 0, "Reject": 1, "Block": 2, "Drop": 3, "?": 4}


def _consolidate(ports):
    ranges = []
    for p in ports:
        if ranges and p == ranges[-1][1] + 1:
            ranges[-1][1] = p
        else:
            ranges.append([p, p])
    return ranges


def _format_ports(port_hits):
    ports = sorted(p for p in port_hits if p >= 0)
    if not ports:
        return ("- (no port)", 0, False)
    n = len(ports)
    if n > SCAN_THRESHOLD:
        return (f"{n} distinct ports ({ports[0]}-{ports[-1]}) - probable "
                f"scan/ephemeral, not a rule candidate", n, True)
    parts = [f"{lo}-{hi}" if hi > lo else str(lo)
             for lo, hi in _consolidate(ports)]
    if len(parts) > MAX_RANGES_SHOWN:
        parts = (parts[:MAX_RANGES_SHOWN]
                 + [f"... (+{len(parts) - MAX_RANGES_SHOWN} more ranges)"])
    return (", ".join(parts), n, False)


def _ts(unix):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(unix))


def build(db, resolver):
    """-> dict with 'rows' (list of group dicts) and 'totals'."""
    groups = {}
    total_flows = 0
    cur = db.execute("SELECT src_ip, dst_ip, proto, dst_port, descr, "
                     "action, hits, first_seen, last_seen FROM flows")
    for src, dst, proto, dport, descr, action, hits, first, last in cur:
        total_flows += 1
        _, src_zone = resolver.resolve(src)
        _, dst_zone = resolver.resolve(dst)
        key = (src_zone, dst_zone, proto, action)
        g = groups.get(key)
        if g is None:
            g = groups[key] = {
                "hits": 0, "first": first, "last": last,
                "ports": {}, "src_ips": set(), "dst_ips": set(), "rules": {},
            }
        g["hits"] += hits
        g["first"] = min(g["first"], first)
        g["last"] = max(g["last"], last)
        g["ports"][dport] = g["ports"].get(dport, 0) + hits
        if len(g["src_ips"]) < 50000:
            g["src_ips"].add(src)
        if len(g["dst_ips"]) < 50000:
            g["dst_ips"].add(dst)
        if descr in g["rules"] or len(g["rules"]) < 50:
            g["rules"][descr] = g["rules"].get(descr, 0) + hits

    rows = []
    for (src_zone, dst_zone, proto, action), g in groups.items():
        ports_disp, n_ports, is_scan = _format_ports(g["ports"])
        top = sorted(g["rules"].items(), key=lambda kv: -kv[1])
        rule_names = "; ".join((name or "(no descr)")
                               for name, _ in top[:MAX_RULE_NAMES])
        if len(top) > MAX_RULE_NAMES:
            rule_names += f"; ... (+{len(top) - MAX_RULE_NAMES} more)"
        candidate = (action == "Allow" and not is_scan
                     and "Unknown" not in (src_zone, dst_zone))
        rows.append({
            "src_zone": src_zone, "dst_zone": dst_zone,
            "proto": proto, "action": action,
            "hits": g["hits"],
            "distinct_src_ips": len(g["src_ips"]),
            "distinct_dst_ips": len(g["dst_ips"]),
            "distinct_ports": n_ports,
            "ports": ports_disp,
            "rule_candidate": bool(candidate),
            "scan_flag": bool(is_scan),
            "rules_matched": rule_names,
            "first_seen": _ts(g["first"]),
            "last_seen": _ts(g["last"]),
            "first_seen_unix": g["first"],
            "last_seen_unix": g["last"],
        })
    rows.sort(key=lambda r: (r["src_zone"], r["dst_zone"],
                             ACTION_ORDER.get(r["action"], 9), r["proto"]))

    totals = {
        "flow_rows": total_flows,
        "groups": len(rows),
        "rule_candidates": sum(1 for r in rows if r["rule_candidate"]),
        "scan_flagged": sum(1 for r in rows if r["scan_flag"]),
        "unknown_zone_groups": sum(
            1 for r in rows if "Unknown" in (r["src_zone"], r["dst_zone"])),
    }
    return {"rows": rows, "totals": totals, "generated_at": int(time.time())}


def to_csv(report):
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_FIELDS, extrasaction="ignore")
    w.writeheader()
    for r in report["rows"]:
        out = dict(r)
        out["rule_candidate"] = "yes" if r["rule_candidate"] else ""
        out["scan_flag"] = "yes" if r["scan_flag"] else ""
        w.writerow(out)
    return buf.getvalue()
