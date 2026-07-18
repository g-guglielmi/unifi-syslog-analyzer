"""Parsing of iptables/netfilter-style firewall syslog lines.

Targets UniFi's CyberSecure SIEM export, but any netfilter-based firewall
emitting  SRC= DST= PROTO= DPT=  key/value lines parses fine.  UniFi
extras handled: a quoted rule description (DESCR="...") and a
[Zone-Action-RuleID] bracket tag whose action marker (-A- / -Allow- ...)
carries the verdict, with a keyword fallback on the description.
"""

import re

RE_FIELD = re.compile(r"\b(SRC|DST|PROTO|DPT)=(\S+)")
RE_DESCR = re.compile(r'DESCR="([^"]*)"|DESCR=(\S+)')
RE_TAG = re.compile(r"\[([^\]\[]{1,120})\]")
RE_TAG_ACTION = re.compile(r"-(Allow|Block|Drop|Reject|[ABDR])-")

ACTION_FROM_MARKER = {"A": "Allow", "B": "Block", "D": "Drop", "R": "Reject",
                      "Allow": "Allow", "Block": "Block",
                      "Drop": "Drop", "Reject": "Reject"}
ACTION_KEYWORDS = [
    ("allow", "Allow"), ("accept", "Allow"),
    ("reject", "Reject"), ("drop", "Drop"),
    ("block", "Block"), ("deny", "Block"),
]


def parse_line(line):
    """One syslog line -> (src_ip, dst_ip, proto, dst_port, descr, action).

    Returns None when the line carries no SRC/DST pair (not a flow line).
    dst_port is -1 when absent (e.g. ICMP); descr is '' when absent —
    sentinels, not NULLs, so aggregation keys dedupe correctly.
    """
    fields = dict(RE_FIELD.findall(line))
    src = fields.get("SRC")
    dst = fields.get("DST")
    if not src or not dst:
        return None

    proto = fields.get("PROTO", "?").upper()
    try:
        dst_port = int(fields["DPT"])
    except (KeyError, ValueError):
        dst_port = -1

    m = RE_DESCR.search(line)
    descr = (m.group(1) if m and m.group(1) is not None
             else (m.group(2) if m else "")) or ""

    action = "?"
    for tag in RE_TAG.findall(line):
        am = RE_TAG_ACTION.search(tag)
        if am:
            action = ACTION_FROM_MARKER[am.group(1)]
            break
    if action == "?":
        low = descr.lower()
        for kw, act in ACTION_KEYWORDS:
            if kw in low:
                action = act
                break

    return (src, dst, proto, dst_port, descr, action)
