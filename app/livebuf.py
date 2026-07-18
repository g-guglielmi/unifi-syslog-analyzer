"""In-memory ring buffer of recent parsed events for the live-log view.

The listener thread appends; HTTP handler threads read incrementally by
sequence number.  Bounded, so memory stays flat no matter the traffic
rate — the live view is a tail, not a second database (the aggregated
flows table remains the durable record).
"""

import threading
from collections import deque


class LiveBuffer:
    def __init__(self, maxlen=2000):
        self._dq = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._seq = 0

    def append(self, ts, src, dst, proto, dst_port, action, descr):
        with self._lock:
            self._seq += 1
            self._dq.append((self._seq, ts, src, dst, proto, dst_port,
                             action, descr))

    def since(self, seq, limit=500):
        """Events with sequence > seq (oldest first), plus the latest seq."""
        with self._lock:
            events = [e for e in self._dq if e[0] > seq]
            latest = self._seq
        events = events[-limit:]
        keys = ("seq", "ts", "src", "dst", "proto", "dst_port",
                "action", "descr")
        return latest, [dict(zip(keys, e)) for e in events]
