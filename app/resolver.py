"""IP -> (network name, zone) resolution from the enumerated networks table.

Resolution happens at report time, never at ingest: flows store raw IPs,
so a corrected or late-arriving network table retroactively fixes zone
attribution on the next report.

Zone semantics:
  * exact gateway-IP match       -> zone "Gateway" (the firewall itself)
  * longest-prefix network match -> that network's zone
  * multicast / broadcast        -> "Multicast" / "Broadcast"
  * unmatched global IP          -> "External" (internet)
  * anything else                -> "Unknown" (table incomplete — visible,
                                    safe failure instead of a wrong zone)
"""

import ipaddress

from store import load_networks, meta_get

_CACHE_MAX = 100_000


class Resolver:
    def __init__(self, db):
        self.db = db
        self._rev = None
        self._nets = []       # (ip_network, name, zone) longest-prefix first
        self._gateways = {}   # ip string -> network name
        self._cache = {}

    def _maybe_reload(self):
        rev = meta_get(self.db, "networks_rev", "0")
        if rev == self._rev:
            return
        nets, gateways = [], {}
        for n in load_networks(self.db):
            try:
                net = ipaddress.ip_network(n["cidr"], strict=False)
            except ValueError:
                continue
            nets.append((net, n["name"], n["zone"]))
            if n.get("gateway_ip"):
                gateways[n["gateway_ip"]] = n["name"]
        nets.sort(key=lambda t: t[0].prefixlen, reverse=True)
        self._nets, self._gateways = nets, gateways
        self._cache.clear()
        self._rev = rev

    def resolve(self, ip_str):
        """-> (network_name, zone)"""
        self._maybe_reload()
        hit = self._cache.get(ip_str)
        if hit is not None:
            return hit
        result = self._resolve_uncached(ip_str)
        if len(self._cache) < _CACHE_MAX:
            self._cache[ip_str] = result
        return result

    def _resolve_uncached(self, ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return ("invalid", "Unknown")
        gw = self._gateways.get(ip_str)
        if gw is not None:
            return (gw + " gateway", "Gateway")
        for net, name, zone in self._nets:
            if ip.version == net.version and ip in net:
                return (name, zone)
        if ip.is_multicast:
            return ("multicast", "Multicast")
        if ip_str == "255.255.255.255":
            return ("broadcast", "Broadcast")
        if ip.is_link_local:
            return ("link-local", "Unknown")
        if ip.is_global:
            return ("internet", "External")
        return ("unmatched", "Unknown")
