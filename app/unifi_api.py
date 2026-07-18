"""UniFi controller API client — network & firewall-zone enumeration.

Stdlib only.  Supports both API layouts:
  * UniFi OS consoles (UDM/UDR/UDM Pro/Cloud Key Gen2 on 443):
      login  POST /api/auth/login
      data   GET  /proxy/network/...
  * legacy self-hosted controllers (:8443):
      login  POST /api/login
      data   GET  /...

Networks come from /api/s/<site>/rest/networkconf (stable for many major
versions).  Zone membership comes from the zone-based-firewall v2 API
when available (Network >= 9.0); otherwise zones fall back to a mapping
from each network's `purpose` field.

A read-only local admin is all this needs.  Self-signed certs are the
norm on controllers, so TLS verification is optional (off by default,
matching how these are deployed on management networks).
"""

import ipaddress
import json
import ssl
import sys
import urllib.error
import urllib.request
from http.cookiejar import CookieJar

PURPOSE_ZONE = {
    "corporate": "Internal",
    "vlan-only": "Internal",
    "guest": "Guest",
    "remote-user-vpn": "VPN",
    "site-vpn": "VPN",
    "vpn-client": "VPN",
    "wan": "External",
}

ZONE_ENDPOINT_CANDIDATES = [
    "/v2/api/site/{site}/firewall/zones",
    "/v2/api/site/{site}/firewall-zones",
]


class UniFiError(Exception):
    pass


class UniFiClient:
    def __init__(self, host, username, password, site="default",
                 verify_ssl=False, timeout=15):
        self.host = host.rstrip("/")
        if "://" not in self.host:
            self.host = "https://" + self.host
        self.username = username
        self.password = password
        self.site = site
        self.timeout = timeout
        self.is_unifi_os = None   # decided at login
        self._csrf = None

        ctx = ssl.create_default_context()
        if not verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPCookieProcessor(CookieJar()))

    def _request(self, method, path, body=None):
        url = self.host + path
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if self._csrf:
            req.add_header("X-CSRF-Token", self._csrf)
        with self._opener.open(req, timeout=self.timeout) as resp:
            csrf = resp.headers.get("X-CSRF-Token") or \
                resp.headers.get("X-Updated-CSRF-Token")
            if csrf:
                self._csrf = csrf
            raw = resp.read()
        return json.loads(raw) if raw else None

    def login(self):
        creds = {"username": self.username, "password": self.password}
        try:
            self._request("POST", "/api/auth/login", creds)
            self.is_unifi_os = True
            return
        except urllib.error.HTTPError as e:
            if e.code not in (400, 401, 404):
                raise UniFiError(f"login failed at /api/auth/login: {e}")
            if e.code == 401:
                raise UniFiError("login rejected (401): check credentials")
        except urllib.error.URLError as e:
            raise UniFiError(f"cannot reach {self.host}: {e.reason}")
        try:
            self._request("POST", "/api/login", creds)
            self.is_unifi_os = False
        except Exception as e:
            raise UniFiError(f"login failed on both API layouts: {e}")

    def _net_path(self, path):
        prefix = "/proxy/network" if self.is_unifi_os else ""
        return prefix + path.format(site=self.site)

    def get_networks(self):
        data = self._request(
            "GET", self._net_path("/api/s/{site}/rest/networkconf"))
        if not isinstance(data, dict) or "data" not in data:
            raise UniFiError("unexpected networkconf response shape")
        return data["data"]

    def get_zones(self):
        """Zone list from the zone-based-firewall API, or None if
        unavailable (pre-9.0 controller, or endpoint moved)."""
        for candidate in ZONE_ENDPOINT_CANDIDATES:
            try:
                data = self._request("GET", self._net_path(candidate))
            except Exception:
                continue
            zones = data.get("data") if isinstance(data, dict) else data
            if isinstance(zones, list):
                return zones
        return None


def fetch_network_rows(client):
    """Enumerate networks and map them to zones.

    Returns rows for store.replace_networks: one per enabled network with
    a local subnet.  UniFi's `ip_subnet` is the gateway address plus
    prefix (e.g. "10.30.50.1/24"), which yields both the CIDR and the
    exact gateway IP.
    """
    client.login()
    nets = client.get_networks()
    zones = client.get_zones()

    zone_by_net_id = {}
    if zones:
        for z in zones:
            zname = z.get("name") or "?"
            for nid in (z.get("network_ids") or z.get("networks") or []):
                if isinstance(nid, dict):
                    nid = nid.get("_id") or nid.get("id")
                if nid:
                    zone_by_net_id[nid] = zname

    rows = []
    for n in nets:
        if not n.get("enabled", True):
            continue
        subnet = n.get("ip_subnet")
        if not subnet:
            continue  # WAN uplinks etc. — no local subnet to attribute
        try:
            iface = ipaddress.ip_interface(subnet)
        except ValueError:
            print(f"[unifi] skipping network {n.get('name')!r}: "
                  f"unparseable ip_subnet {subnet!r}", file=sys.stderr)
            continue
        purpose = n.get("purpose", "")
        zone = (zone_by_net_id.get(n.get("_id"))
                or PURPOSE_ZONE.get(purpose, "Internal"))
        rows.append({
            "key": n.get("_id") or "api:" + n.get("name", "?"),
            "name": n.get("name", "?"),
            "vlan_id": n.get("vlan"),
            "cidr": str(iface.network),
            "gateway_ip": str(iface.ip),
            "zone": zone,
        })
    return rows, ("zones-api" if zones else "purpose-fallback")
