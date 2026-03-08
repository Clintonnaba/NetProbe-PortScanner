"""
scanner_core.py — Port Scanner Logic
======================================
Module: ST5062CEM - Programming and Algorithm 2

Contains all scanning logic, custom data structures, and no GUI dependencies.
This module is imported by both port_scanner.py (GUI) and test_port_scanner.py (tests).
"""

import socket
import threading
import time
from datetime import datetime
from queue import Queue, Empty


# ─────────────────────────────────────────────
# DATA STRUCTURES (user-defined, not built-in)
# ─────────────────────────────────────────────

class ScanResult:
    """
    Represents the result of scanning a single TCP port.

    Attributes:
        port     (int):  The port number that was scanned.
        state    (str):  "open", "closed", or "filtered".
        service  (str):  The guessed service name (e.g. "HTTP").
        banner   (str):  Optional service banner if grabbed.
        timestamp (datetime): When this result was recorded.
    """

    def __init__(self, port: int, state: str, service: str, banner: str = ""):
        self.port = port
        self.state = state
        self.service = service
        self.banner = banner
        self.timestamp = datetime.now()

    def __repr__(self):
        return f"ScanResult(port={self.port}, state={self.state}, service={self.service})"


class ResultList:
    """
    Custom singly-linked list for storing ScanResult objects.
    Avoids reliance on Python's built-in list so the data structure
    is user-defined per the module requirements.

    Operations:
        append()         – O(n) tail insertion
        to_sorted_list() – O(n²) insertion sort by port number
        filter_open()    – O(n) traversal with state check
        clear()          – O(1) reset
    """

    class _Node:
        """Internal node for the linked list."""
        __slots__ = ("data", "next")

        def __init__(self, data: ScanResult):
            self.data: ScanResult = data
            self.next: "ResultList._Node | None" = None

    def __init__(self):
        self._head: "ResultList._Node | None" = None
        self._size: int = 0

    # ── Public API ───────────────────────────

    def append(self, data: ScanResult) -> None:
        """Append a ScanResult to the end of the list. O(n)."""
        node = self._Node(data)
        if self._head is None:
            self._head = node
        else:
            current = self._head
            while current.next:
                current = current.next
            current.next = node
        self._size += 1

    def to_sorted_list(self) -> list:
        """
        Return a plain Python list sorted by port number in ascending order.
        Uses insertion sort – O(n²) – to avoid built-in sort().
        """
        # First, collect all nodes into a plain array for sorting
        items: list[ScanResult] = []
        current = self._head
        while current:
            items.append(current.data)
            current = current.next

        # Insertion sort by port number
        for i in range(1, len(items)):
            key = items[i]
            j = i - 1
            while j >= 0 and items[j].port > key.port:
                items[j + 1] = items[j]
                j -= 1
            items[j + 1] = key

        return items

    def filter_open(self) -> list:
        """Return only open-state results, sorted by port. O(n)."""
        return [r for r in self.to_sorted_list() if r.state == "open"]

    def clear(self) -> None:
        """Reset the list to empty. O(1)."""
        self._head = None
        self._size = 0

    def __len__(self) -> int:
        return self._size


# ─────────────────────────────────────────────
# SERVICE LOOKUP TABLE
# ─────────────────────────────────────────────

# A hand-crafted dictionary of the most common port → service mappings.
# Avoids requiring a full OS service database.
COMMON_SERVICES: dict[int, str] = {
    20: "FTP-Data",   21: "FTP",         22: "SSH",         23: "Telnet",
    25: "SMTP",       53: "DNS",          67: "DHCP",        68: "DHCP",
    80: "HTTP",       110: "POP3",        119: "NNTP",       123: "NTP",
    135: "RPC",       139: "NetBIOS",     143: "IMAP",       161: "SNMP",
    194: "IRC",       389: "LDAP",        443: "HTTPS",      445: "SMB",
    465: "SMTPS",     514: "Syslog",      587: "SMTP-Alt",   631: "IPP",
    636: "LDAPS",     993: "IMAPS",       995: "POP3S",      1080: "SOCKS",
    1433: "MSSQL",    1521: "Oracle",     1723: "PPTP",      2049: "NFS",
    3306: "MySQL",    3389: "RDP",        4444: "Metasploit",5432: "PostgreSQL",
    5900: "VNC",      6379: "Redis",      6667: "IRC",       8080: "HTTP-Alt",
    8443: "HTTPS-Alt",8888: "HTTP-Alt2",  9200: "Elasticsearch", 27017: "MongoDB",
}


# ─────────────────────────────────────────────
# SCANNER FUNCTIONS
# ─────────────────────────────────────────────

def resolve_host(host: str) -> str:
    """
    Resolve a hostname string to an IPv4 address string.

    Args:
        host: A hostname or IP address string.

    Returns:
        The resolved IPv4 address as a string.

    Raises:
        ValueError: If the hostname cannot be resolved.
    """
    try:
        return socket.gethostbyname(host.strip())
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve host '{host}': {exc}") from exc


def get_service_name(port: int) -> str:
    """
    Return the service name for a given port number.
    Checks the local COMMON_SERVICES dict first; falls back to
    the OS socket database; returns "Unknown" if neither works.

    Args:
        port: An integer port number (1–65535).

    Returns:
        Service name string.
    """
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port)
    except OSError:
        return "Unknown"


def grab_banner(sock: socket.socket, timeout: float = 1.0) -> str:
    """
    Attempt to read a service banner from an already-connected socket.

    Args:
        sock:    An open, connected TCP socket.
        timeout: Seconds to wait for data.

    Returns:
        The first line of the banner (max 80 chars), or "" on failure.
    """
    try:
        sock.settimeout(timeout)
        raw = sock.recv(1024).decode("utf-8", errors="replace").strip()
        return raw.splitlines()[0][:80] if raw else ""
    except Exception:
        return ""


def scan_port(host: str, port: int, timeout: float,
              grab_banners: bool) -> ScanResult:
    """
    Attempt a TCP connect scan on a single port.

    Uses socket.connect_ex() so it does not raise on connection refusal.
    A return code of 0 means the port is open; anything else is closed.
    A socket.timeout exception indicates the port is filtered/firewalled.

    Args:
        host:         Target IP address string.
        port:         Port number to scan.
        timeout:      Seconds to wait for a connection.
        grab_banners: Whether to attempt reading a service banner.

    Returns:
        A ScanResult object with state "open", "closed", or "filtered".
    """
    service = get_service_name(port)
    banner = ""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            code = sock.connect_ex((host, port))
            if code == 0:
                # Port accepted the connection → open
                if grab_banners:
                    banner = grab_banner(sock)
                return ScanResult(port, "open", service, banner)
            else:
                # Connection refused or other OS error → closed
                return ScanResult(port, "closed", service)
    except socket.timeout:
        # No response within timeout → likely firewalled
        return ScanResult(port, "filtered", service)
    except OSError:
        return ScanResult(port, "closed", service)


# ─────────────────────────────────────────────
# PORT SCANNER (multi-threaded engine)
# ─────────────────────────────────────────────

class PortScanner:
    """
    Multi-threaded TCP port scanner.

    Architecture:
        - A work Queue is pre-populated with all port numbers to scan.
        - A configurable pool of daemon threads drain the queue, each
          calling scan_port() and depositing results.
        - A separate watcher thread monitors the queue and fires
          done_callback when all ports have been processed.
        - A threading.Event allows graceful stop mid-scan.

    Callbacks (all optional, called from background threads):
        progress_callback(scanned: int, total: int)
        result_callback(result: ScanResult)
        done_callback(results: ResultList, elapsed_seconds: float)
    """

    def __init__(self,
                 host: str,
                 port_start: int,
                 port_end: int,
                 timeout: float = 1.0,
                 threads: int = 100,
                 grab_banners: bool = False,
                 progress_callback=None,
                 result_callback=None,
                 done_callback=None):

        self.host = host
        self.port_start = port_start
        self.port_end = port_end
        self.timeout = timeout
        self.threads = threads
        self.grab_banners = grab_banners
        self.progress_callback = progress_callback
        self.result_callback = result_callback
        self.done_callback = done_callback

        # Internal state
        self._stop_event = threading.Event()
        self._work_queue: Queue = Queue()
        self._results = ResultList()
        self._lock = threading.Lock()   # Protects _scanned counter
        self._scanned = 0
        self._total = port_end - port_start + 1
        self._start_time: float = 0.0

    # ── Public API ───────────────────────────

    def start(self) -> None:
        """Begin the scan. Non-blocking; scanning runs on daemon threads."""
        self._stop_event.clear()
        self._results.clear()
        self._scanned = 0

        # Fill the work queue
        for port in range(self.port_start, self.port_end + 1):
            self._work_queue.put(port)

        self._start_time = time.perf_counter()

        # Spawn worker pool (capped by number of ports to avoid idle threads)
        num_threads = min(self.threads, self._total)
        for _ in range(num_threads):
            threading.Thread(target=self._worker, daemon=True).start()

        # Watcher fires done_callback after all work is consumed
        threading.Thread(target=self._watcher, daemon=True).start()

    def stop(self) -> None:
        """Signal all workers to finish their current port and exit."""
        self._stop_event.set()

    # ── Internal helpers ─────────────────────

    def _worker(self) -> None:
        """Worker thread: pull ports from queue and scan them until stopped."""
        while not self._stop_event.is_set():
            try:
                port = self._work_queue.get(timeout=0.1)
            except Empty:
                break   # Queue drained — exit normally

            result = scan_port(self.host, port, self.timeout, self.grab_banners)

            with self._lock:
                self._results.append(result)
                self._scanned += 1
                scanned = self._scanned

            if self.result_callback:
                self.result_callback(result)
            if self.progress_callback:
                self.progress_callback(scanned, self._total)

            self._work_queue.task_done()

    def _watcher(self) -> None:
        """Wait until the queue is fully drained then notify caller."""
        self._work_queue.join()
        elapsed = time.perf_counter() - self._start_time
        if self.done_callback:
            self.done_callback(self._results, elapsed)
