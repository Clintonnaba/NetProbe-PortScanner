"""
netprobe.py  —  NetProbe Port Scanner  (self-contained)
=========================================================
Module : ST5062CEM - Programming and Algorithm 2
Usage  : python netprobe.py

Everything lives in this single file:
  • Custom data structures (ResultList linked-list, ScanResult)
  • Multi-threaded scanning engine
  • Full Tkinter GUI

If tkinter is missing:
  Windows  →  reinstall Python and tick "tcl/tk and IDLE" in the installer
  Ubuntu   →  sudo apt install python3-tk
  macOS    →  brew install python-tk
"""

# ── Startup guard ────────────────────────────────────────────────────────────
import sys

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
except ModuleNotFoundError:
    sys.exit(
        "\n[ERROR] tkinter is not installed.\n"
        "  Windows : reinstall Python → check 'tcl/tk and IDLE'\n"
        "  Ubuntu  : sudo apt install python3-tk\n"
        "  macOS   : brew install python-tk\n"
    )

# ── Standard library imports ─────────────────────────────────────────────────
import socket
import threading
import time
from datetime import datetime
from queue import Queue, Empty


# =============================================================================
# SECTION 1 — CUSTOM DATA STRUCTURES
# =============================================================================

class ScanResult:
    """
    Value object representing the outcome of scanning one TCP port.

    Attributes
    ----------
    port      : int   – port number (1–65535)
    state     : str   – 'open' | 'closed' | 'filtered'
    service   : str   – guessed service name (e.g. 'HTTP')
    banner    : str   – first line of service banner, or ''
    timestamp : datetime – when the result was recorded
    """

    def __init__(self, port: int, state: str, service: str, banner: str = ""):
        self.port      = port
        self.state     = state
        self.service   = service
        self.banner    = banner
        self.timestamp = datetime.now()

    def __repr__(self):
        return f"ScanResult(port={self.port}, state={self.state!r}, service={self.service!r})"


class ResultList:
    """
    User-defined singly-linked list for ScanResult objects.

    Using a hand-rolled linked list (rather than Python's built-in list)
    satisfies the module requirement of custom data structures.

    Complexity
    ----------
    append          : O(n)  – walks to tail each time
    to_sorted_list  : O(n²) – insertion sort (intentional for coursework)
    filter_open     : O(n)  – single traversal
    clear           : O(1)
    """

    # ── Internal node ────────────────────────────────
    class _Node:
        __slots__ = ("data", "next")
        def __init__(self, data: ScanResult):
            self.data = data
            self.next = None   # type: ignore[assignment]

    # ── Constructor ──────────────────────────────────
    def __init__(self):
        self._head = None   # Points to first node (or None if empty)
        self._size = 0

    # ── Public interface ─────────────────────────────

    def append(self, data: ScanResult) -> None:
        """Insert data at the tail of the list."""
        node = self._Node(data)
        if self._head is None:
            self._head = node
        else:
            cur = self._head
            while cur.next:          # Walk to the last node
                cur = cur.next
            cur.next = node
        self._size += 1

    def to_sorted_list(self) -> list:
        """
        Collect all nodes into a list then sort by port number
        using insertion sort (no built-in sort used).
        """
        items: list = []
        cur = self._head
        while cur:
            items.append(cur.data)
            cur = cur.next

        # Insertion sort — O(n²)
        for i in range(1, len(items)):
            key = items[i]
            j   = i - 1
            while j >= 0 and items[j].port > key.port:
                items[j + 1] = items[j]
                j -= 1
            items[j + 1] = key

        return items

    def filter_open(self) -> list:
        """Return only open-state results, sorted ascending by port."""
        return [r for r in self.to_sorted_list() if r.state == "open"]

    def clear(self) -> None:
        """Reset the list to empty in O(1)."""
        self._head = None
        self._size = 0

    def __len__(self) -> int:
        return self._size


# =============================================================================
# SECTION 2 — SCANNER LOGIC
# =============================================================================

# Known port → service name mappings (avoids needing OS service database)
_SERVICES: dict = {
    20: "FTP-Data",  21: "FTP",       22: "SSH",       23: "Telnet",
    25: "SMTP",      53: "DNS",        67: "DHCP",      68: "DHCP",
    80: "HTTP",     110: "POP3",      119: "NNTP",     123: "NTP",
   135: "RPC",      139: "NetBIOS",   143: "IMAP",     161: "SNMP",
   194: "IRC",      389: "LDAP",      443: "HTTPS",    445: "SMB",
   465: "SMTPS",    514: "Syslog",    587: "SMTP-Alt", 631: "IPP",
   636: "LDAPS",    993: "IMAPS",     995: "POP3S",   1080: "SOCKS",
  1433: "MSSQL",   1521: "Oracle",   1723: "PPTP",    2049: "NFS",
  3306: "MySQL",   3389: "RDP",      4444: "MSF",     5432: "PostgreSQL",
  5900: "VNC",     6379: "Redis",    6667: "IRC",     8080: "HTTP-Alt",
  8443: "HTTPS-Alt",8888: "HTTP-Alt2",9200: "Elastic",27017: "MongoDB",
}


def _resolve_host(host: str) -> str:
    """
    Resolve a hostname to an IPv4 string.
    Raises ValueError with a human-readable message on failure.
    """
    try:
        return socket.gethostbyname(host.strip())
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve '{host}': {exc}") from exc


def _service_name(port: int) -> str:
    """Return the service name for a port from table or OS DB."""
    if port in _SERVICES:
        return _SERVICES[port]
    try:
        return socket.getservbyport(port)
    except OSError:
        return "Unknown"


def _grab_banner(sock: socket.socket, timeout: float = 1.0) -> str:
    """
    Try to read the first line of a service banner (max 80 chars).
    Returns '' on any error so callers do not need to handle exceptions.
    """
    try:
        sock.settimeout(timeout)
        raw = sock.recv(1024).decode("utf-8", errors="replace").strip()
        return raw.splitlines()[0][:80] if raw else ""
    except Exception:
        return ""


def _scan_port(host: str, port: int, timeout: float,
               grab_banners: bool) -> ScanResult:
    """
    Perform a TCP connect scan on one port and return a ScanResult.

    State mapping
    -------------
    connect_ex == 0        → 'open'
    connect_ex != 0        → 'closed'
    socket.timeout raised  → 'filtered'  (no response, likely firewalled)
    OSError raised         → 'closed'
    """
    service = _service_name(port)
    banner  = ""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            code = s.connect_ex((host, port))
            if code == 0:                         # Port is open
                if grab_banners:
                    banner = _grab_banner(s)
                return ScanResult(port, "open", service, banner)
            return ScanResult(port, "closed", service)
    except socket.timeout:
        return ScanResult(port, "filtered", service)
    except OSError:
        return ScanResult(port, "closed", service)


class PortScanner:
    """
    Multi-threaded TCP port scanner.

    Design
    ------
    • Work Queue   – pre-filled with every port number to scan
    • Thread pool  – N daemon threads drain the queue concurrently
    • Stop event   – threading.Event lets the user halt mid-scan
    • Watcher      – extra thread fires done_callback when queue is empty

    All three callbacks are optional and are called from worker threads,
    so GUI code must marshal them to the main thread via widget.after().
    """

    def __init__(self, host, port_start, port_end,
                 timeout=1.0, threads=100, grab_banners=False,
                 progress_callback=None,
                 result_callback=None,
                 done_callback=None):

        self.host          = host
        self.port_start    = port_start
        self.port_end      = port_end
        self.timeout       = timeout
        self.threads       = threads
        self.grab_banners  = grab_banners
        self._on_progress  = progress_callback   # fn(scanned, total)
        self._on_result    = result_callback     # fn(ScanResult)
        self._on_done      = done_callback       # fn(ResultList, elapsed)

        self._stop    = threading.Event()
        self._queue   = Queue()
        self._results = ResultList()
        self._lock    = threading.Lock()
        self._scanned = 0
        self._total   = port_end - port_start + 1
        self._t0      = 0.0

    # ── Public ───────────────────────────────────────

    def start(self):
        """Populate queue and spawn worker + watcher threads."""
        self._stop.clear()
        self._results.clear()
        self._scanned = 0

        for p in range(self.port_start, self.port_end + 1):
            self._queue.put(p)

        self._t0 = time.perf_counter()
        n = min(self.threads, self._total)

        for _ in range(n):
            threading.Thread(target=self._worker, daemon=True).start()
        threading.Thread(target=self._watcher, daemon=True).start()

    def stop(self):
        """Signal all workers to stop after finishing their current port."""
        self._stop.set()

    # ── Private ──────────────────────────────────────

    def _worker(self):
        """Worker: pull ports from queue and scan until stopped or empty."""
        while not self._stop.is_set():
            try:
                port = self._queue.get(timeout=0.1)
            except Empty:
                break
            res = _scan_port(self.host, port, self.timeout, self.grab_banners)
            with self._lock:
                self._results.append(res)
                self._scanned += 1
                scanned = self._scanned
            if self._on_result:
                self._on_result(res)
            if self._on_progress:
                self._on_progress(scanned, self._total)
            self._queue.task_done()

    def _watcher(self):
        """Block until queue is fully drained, then call done_callback."""
        self._queue.join()
        elapsed = time.perf_counter() - self._t0
        if self._on_done:
            self._on_done(self._results, elapsed)


# =============================================================================
# SECTION 3 — GUI  (Tkinter, dark terminal theme)
# =============================================================================

# ── Palette ──────────────────────────────────────────────────────────────────
BG      = "#0d1117"   # Main background
PANEL   = "#161b22"   # Card / panel background
BORDER  = "#30363d"   # Subtle border
ACCENT  = "#39d353"   # Green accent (open ports, buttons)
RED     = "#f85149"   # Stop button / errors
YELLOW  = "#e3b341"   # Filtered ports
FG      = "#e6edf3"   # Primary text
FG2     = "#8b949e"   # Secondary / label text

# ── Fonts ─────────────────────────────────────────────────────────────────────
F_MONO   = ("Courier New", 10)
F_MONO_S = ("Courier New", 9)
F_SANS   = ("Segoe UI",    10)
F_SANS_S = ("Segoe UI",     9)
F_HEAD   = ("Courier New", 18, "bold")


class _Tip:
    """Minimal hover tooltip."""
    def __init__(self, w, text):
        self._w, self._text, self._win = w, text, None
        w.bind("<Enter>", self._show)
        w.bind("<Leave>", self._hide)

    def _show(self, _=None):
        x = self._w.winfo_rootx() + 22
        y = self._w.winfo_rooty() + 22
        self._win = tw = tk.Toplevel(self._w)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        tk.Label(tw, text=self._text, bg="#21262d", fg=FG2,
                 font=F_SANS_S, padx=7, pady=4, relief="flat").pack()

    def _hide(self, _=None):
        if self._win:
            self._win.destroy()
            self._win = None


class NetProbeApp(tk.Tk):
    """
    NetProbe main window.

    Layout (top → bottom)
    ─────────────────────
    Header bar      branding + live clock
    Green rule      2 px accent divider
    Controls        host · ports · options · buttons
    Progress bar    completion %
    Results panel   sortable Treeview
    Status bar      one-line messages
    """

    def __init__(self):
        super().__init__()
        self.title("NetProbe — Port Scanner")
        self.geometry("1000x720")
        self.minsize(820, 560)
        self.configure(bg=BG)
        # Try to set a window icon colour on supported platforms
        try:
            self.tk.call("wm", "iconphoto", self._w, tk.PhotoImage())
        except Exception:
            pass

        # State
        self._scanner: PortScanner | None = None
        self._active   = False
        self._t_start  = 0.0
        self._store    = ResultList()

        self._build_styles()
        self._build_ui()

    # =========================================================================
    # TTK STYLE SETUP
    # =========================================================================

    def _build_styles(self):
        s = ttk.Style(self)
        s.theme_use("clam")

        # Progress bar
        s.configure("G.Horizontal.TProgressbar",
                    troughcolor=PANEL, background=ACCENT,
                    bordercolor=BORDER, darkcolor=ACCENT, lightcolor=ACCENT,
                    thickness=8)

        # Results Treeview
        s.configure("R.Treeview",
                    background=PANEL, foreground=FG,
                    fieldbackground=PANEL, rowheight=26,
                    font=F_MONO_S, borderwidth=0, relief="flat")
        s.configure("R.Treeview.Heading",
                    background="#21262d", foreground=FG2,
                    font=(F_SANS_S[0], F_SANS_S[1], "bold"), relief="flat")
        s.map("R.Treeview",
              background=[("selected", "#1f4068")],
              foreground=[("selected", FG)])

        # Scrollbar
        s.configure("D.Vertical.TScrollbar",
                    troughcolor=PANEL, background=BORDER,
                    arrowcolor=FG2, bordercolor=PANEL, relief="flat")

    # =========================================================================
    # UI CONSTRUCTION
    # =========================================================================

    def _build_ui(self):
        self._mk_header()
        self._mk_controls()
        self._mk_progress()
        self._mk_results()
        self._mk_statusbar()

    # ── Header ───────────────────────────────────────────────────────────────

    def _mk_header(self):
        hdr = tk.Frame(self, bg=PANEL, height=62)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        # Logo text
        tk.Label(hdr, text="⬡  NetProbe", font=F_HEAD,
                 fg=ACCENT, bg=PANEL).pack(side="left", padx=22, pady=10)
        tk.Label(hdr, text="Port Scanner  ·  ST5062CEM",
                 font=F_SANS_S, fg=FG2, bg=PANEL).pack(side="left")

        # Live clock (top-right)
        self._v_clock = tk.StringVar()
        tk.Label(hdr, textvariable=self._v_clock, font=F_MONO_S,
                 fg=FG2, bg=PANEL).pack(side="right", padx=22)
        self._tick_clock()

        # Green rule
        tk.Frame(self, bg=ACCENT, height=2).pack(fill="x")

    # ── Controls panel ───────────────────────────────────────────────────────

    def _mk_controls(self):
        outer = tk.Frame(self, bg=BG, padx=22, pady=14)
        outer.pack(fill="x")

        # ── Row 1: Target + port range ────────────
        r1 = tk.Frame(outer, bg=BG)
        r1.pack(fill="x", pady=(0, 9))

        self._lbl(r1, "Target Host / IP").pack(side="left")
        self._v_host = tk.StringVar(value="scanme.nmap.org")
        he = self._ent(r1, self._v_host, 26)
        he.pack(side="left", padx=(6, 22))
        _Tip(he, "Hostname or IPv4 address to scan")

        self._lbl(r1, "Start Port").pack(side="left")
        self._v_p0 = tk.StringVar(value="1")
        self._ent(r1, self._v_p0, 7).pack(side="left", padx=(6, 20))

        self._lbl(r1, "End Port").pack(side="left")
        self._v_p1 = tk.StringVar(value="1024")
        self._ent(r1, self._v_p1, 7).pack(side="left", padx=(6, 22))

        # Quick presets
        self._lbl(r1, "Quick:").pack(side="left")
        for lbl, a, b in [("Top 100", 1, 100),
                           ("Common 1024", 1, 1024),
                           ("Extended 10k", 1, 10000),
                           ("All 65535", 1, 65535)]:
            tk.Button(r1, text=lbl, font=F_SANS_S, bg=BORDER, fg=FG2,
                      relief="flat", cursor="hand2", padx=7, pady=2,
                      activebackground="#3d444d", activeforeground=FG,
                      command=lambda a=a, b=b: self._set_range(a, b)
                      ).pack(side="left", padx=2)

        # ── Row 2: Options ────────────────────────
        r2 = tk.Frame(outer, bg=BG)
        r2.pack(fill="x", pady=(0, 9))

        self._lbl(r2, "Threads").pack(side="left")
        self._v_thr = tk.StringVar(value="150")
        te = self._ent(r2, self._v_thr, 6)
        te.pack(side="left", padx=(6, 20))
        _Tip(te, "Concurrent threads (1–500). Higher = faster but heavier.")

        self._lbl(r2, "Timeout  (s)").pack(side="left")
        self._v_to = tk.StringVar(value="0.8")
        toe = self._ent(r2, self._v_to, 6)
        toe.pack(side="left", padx=(6, 22))
        _Tip(toe, "Seconds to wait per connection attempt.")

        def _chk(parent, text, var):
            return tk.Checkbutton(parent, text=text, variable=var,
                                  bg=BG, fg=FG2, selectcolor="#21262d",
                                  activebackground=BG, activeforeground=FG,
                                  font=F_SANS_S, cursor="hand2",
                                  highlightthickness=0)

        self._v_ban  = tk.BooleanVar(value=False)
        self._v_open = tk.BooleanVar(value=True)
        _chk(r2, "Grab banners",       self._v_ban ).pack(side="left", padx=(0, 16))
        _chk(r2, "Show open only",     self._v_open).pack(side="left")

        # ── Row 3: Action buttons ─────────────────
        r3 = tk.Frame(outer, bg=BG)
        r3.pack(fill="x")

        self._btn_start = self._big_btn(r3, "▶  Start Scan", ACCENT,   BG,    self._do_start)
        self._btn_stop  = self._big_btn(r3, "■  Stop",       RED,      BG,    self._do_stop)
        self._btn_exp   = self._big_btn(r3, "↓  Export",     BORDER,   FG2,   self._do_export)
        self._btn_clr   = self._big_btn(r3, "✕  Clear",      BORDER,   FG2,   self._do_clear)

        self._btn_start.pack(side="left", padx=(0, 10))
        self._btn_stop.pack(side="left",  padx=(0, 10))
        self._btn_stop.config(state="disabled")
        self._btn_exp.pack(side="left",   padx=(0,  8))
        self._btn_clr.pack(side="left")

        # Live elapsed timer (right side of button row)
        self._v_elapsed = tk.StringVar(value="")
        tk.Label(r3, textvariable=self._v_elapsed, font=F_MONO_S,
                 fg=ACCENT, bg=BG).pack(side="right")

    # ── Progress bar ─────────────────────────────────────────────────────────

    def _mk_progress(self):
        pf = tk.Frame(self, bg=BG, padx=22, pady=3)
        pf.pack(fill="x")

        self._v_pct = tk.DoubleVar(value=0)
        ttk.Progressbar(pf, variable=self._v_pct, maximum=100,
                        style="G.Horizontal.TProgressbar",
                        length=200).pack(fill="x")

        self._lbl_prog = tk.Label(pf, text="", font=F_SANS_S, fg=FG2, bg=BG)
        self._lbl_prog.pack(anchor="e")

    # ── Results table ─────────────────────────────────────────────────────────

    def _mk_results(self):
        rf = tk.Frame(self, bg=BG, padx=22, pady=6)
        rf.pack(fill="both", expand=True)

        # Section label + row counter
        top = tk.Frame(rf, bg=BG)
        top.pack(fill="x", pady=(0, 5))
        tk.Label(top, text="SCAN RESULTS",
                 font=("Courier New", 10, "bold"),
                 fg=ACCENT, bg=BG).pack(side="left")
        self._v_count = tk.StringVar(value="")
        tk.Label(top, textvariable=self._v_count,
                 font=F_SANS_S, fg=FG2, bg=BG).pack(side="right")

        # Treeview
        cols = ("Port", "State", "Service", "Banner")
        self._tree = ttk.Treeview(rf, columns=cols, show="headings",
                                  style="R.Treeview", selectmode="browse")

        for col, w in zip(cols, [72, 88, 140, 0]):
            self._tree.heading(col, text=col,
                               command=lambda c=col: self._sort(c))
            # Banner column expands to fill remaining width
            if w:
                self._tree.column(col, width=w, anchor="w", stretch=False)
            else:
                self._tree.column(col, width=400, anchor="w", stretch=True)

        sb = ttk.Scrollbar(rf, orient="vertical",
                           command=self._tree.yview,
                           style="D.Vertical.TScrollbar")
        self._tree.configure(yscrollcommand=sb.set)
        self._tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        # Colour tags per state
        self._tree.tag_configure("open",     background="#0a1f10", foreground=ACCENT)
        self._tree.tag_configure("closed",   background=PANEL,    foreground="#4a5568")
        self._tree.tag_configure("filtered", background="#1a160a", foreground=YELLOW)

    # ── Status bar ────────────────────────────────────────────────────────────

    def _mk_statusbar(self):
        sb = tk.Frame(self, bg=PANEL, height=28)
        sb.pack(fill="x", side="bottom")
        sb.pack_propagate(False)

        # Green left accent bar
        tk.Frame(sb, bg=ACCENT, width=4).pack(side="left", fill="y")

        self._v_status = tk.StringVar(
            value="Ready — enter a target and press  ▶ Start Scan")
        tk.Label(sb, textvariable=self._v_status, font=F_SANS_S,
                 fg=FG2, bg=PANEL, anchor="w").pack(side="left",
                                                     padx=12, fill="x")

    # =========================================================================
    # WIDGET FACTORIES
    # =========================================================================

    def _lbl(self, parent, text):
        return tk.Label(parent, text=text, font=F_SANS_S,
                        fg=FG2, bg=BG)

    def _ent(self, parent, var, width=14):
        return tk.Entry(parent, textvariable=var, width=width,
                        bg="#21262d", fg=FG, insertbackground=ACCENT,
                        relief="flat", font=F_SANS,
                        highlightthickness=1,
                        highlightcolor=ACCENT,
                        highlightbackground=BORDER)

    def _big_btn(self, parent, text, bg, fg, cmd):
        return tk.Button(parent, text=text, command=cmd,
                         bg=bg, fg=fg,
                         font=("Segoe UI", 10, "bold"),
                         relief="flat", cursor="hand2",
                         padx=16, pady=7,
                         activebackground=bg,
                         activeforeground=fg,
                         bd=0)

    # =========================================================================
    # ACTIONS
    # =========================================================================

    def _do_start(self):
        """Validate inputs → resolve host → launch PortScanner."""
        host_raw = self._v_host.get().strip()
        if not host_raw:
            self._err("Please enter a hostname or IP address.")
            return

        try:
            p0      = int(self._v_p0.get())
            p1      = int(self._v_p1.get())
            timeout = float(self._v_to.get())
            threads = int(self._v_thr.get())
        except ValueError:
            self._err("Port range, timeout, and threads must be numbers.")
            return

        if not (1 <= p0 <= p1 <= 65535):
            self._err("Port range must satisfy  1 ≤ start ≤ end ≤ 65535.")
            return
        if not (1 <= threads <= 500):
            self._err("Threads must be 1–500.")
            return
        if not (0.01 <= timeout <= 30):
            self._err("Timeout must be 0.01–30 seconds.")
            return

        try:
            ip = _resolve_host(host_raw)
        except ValueError as exc:
            self._err(str(exc))
            return

        # Reset UI
        self._do_clear(keep=True)
        self._store.clear()
        self._active  = True
        self._t_start = time.time()
        self._btn_start.config(state="disabled")
        self._btn_stop.config(state="normal")
        self._v_elapsed.set("")
        self._v_pct.set(0)

        total = p1 - p0 + 1
        self._status(
            f"Scanning  {ip}  │  ports {p0}–{p1}  "
            f"│  {total:,} total  │  {threads} threads  │  timeout {timeout}s")
        self._tick_elapsed()

        self._scanner = PortScanner(
            host=ip, port_start=p0, port_end=p1,
            timeout=timeout, threads=threads,
            grab_banners=self._v_ban.get(),
            progress_callback=self._cb_progress,
            result_callback=self._cb_result,
            done_callback=self._cb_done,
        )
        self._scanner.start()

    def _do_stop(self):
        if self._scanner:
            self._scanner.stop()
        self._active = False
        self._status("Scan stopped by user.")
        self._btn_start.config(state="normal")
        self._btn_stop.config(state="disabled")

    def _do_export(self):
        items = self._tree.get_children()
        if not items:
            messagebox.showinfo("Export", "No results to export.", parent=self)
            return
        path = filedialog.asksaveasfilename(
            parent=self, defaultextension=".txt",
            filetypes=[("Text file", "*.txt"), ("All files", "*.*")],
            title="Export scan results")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"NetProbe Scan  —  {datetime.now():%Y-%m-%d %H:%M:%S}\n")
            fh.write(f"Target : {self._v_host.get()}\n")
            fh.write(f"Range  : {self._v_p0.get()}–{self._v_p1.get()}\n")
            fh.write("─" * 72 + "\n")
            fh.write(f"{'Port':<8}{'State':<10}{'Service':<18}Banner\n")
            fh.write("─" * 72 + "\n")
            for iid in items:
                v = self._tree.item(iid, "values")
                fh.write(f"{v[0]:<8}{v[1]:<10}{v[2]:<18}{v[3]}\n")
        self._status(f"Exported → {path}")

    def _do_clear(self, keep=False):
        for row in self._tree.get_children():
            self._tree.delete(row)
        self._v_pct.set(0)
        self._lbl_prog.config(text="")
        self._v_count.set("")
        if not keep:
            self._v_elapsed.set("")
            self._status("Ready.")

    # =========================================================================
    # SCANNER CALLBACKS  (fired from worker threads → marshalled via after())
    # =========================================================================

    def _cb_progress(self, scanned, total):
        self.after(0, self._ui_progress, scanned, total)

    def _cb_result(self, result: ScanResult):
        # Honour "show open only" filter without touching the worker
        if self._v_open.get() and result.state != "open":
            return
        self.after(0, self._ui_row, result)

    def _cb_done(self, results: ResultList, elapsed: float):
        n_open = len(results.filter_open())
        self.after(0, self._ui_done, results, elapsed, n_open)

    # ── UI updaters (main-thread only) ───────────────────────────────────────

    def _ui_progress(self, scanned, total):
        pct = scanned / total * 100 if total else 0
        self._v_pct.set(pct)
        self._lbl_prog.config(
            text=f"{scanned:,} / {total:,} ports  ({pct:.1f} %)")

    def _ui_row(self, r: ScanResult):
        vals = (r.port, r.state.upper(), r.service, r.banner)
        self._tree.insert("", "end", values=vals, tags=(r.state,))
        kids = self._tree.get_children()
        if kids:
            self._tree.see(kids[-1])       # Auto-scroll
        n = len(kids)
        self._v_count.set(f"{n} row{'s' if n != 1 else ''}")

    def _ui_done(self, results, elapsed, n_open):
        self._active = False
        self._store  = results
        self._btn_start.config(state="normal")
        self._btn_stop.config(state="disabled")
        self._v_pct.set(100)
        m, s = divmod(elapsed, 60)
        ts = f"{int(m)}m {s:.1f}s" if m else f"{s:.2f}s"
        self._v_elapsed.set(f"⏱ {ts}")
        self._status(
            f"Done  ·  {len(results):,} ports scanned  ·  "
            f"{n_open} open  ·  {ts}")

    # =========================================================================
    # COLUMN SORTING
    # =========================================================================

    def _sort(self, col: str):
        """Click a column header to sort results by that column."""
        rows = [(self._tree.set(k, col), k)
                for k in self._tree.get_children("")]
        try:
            rows.sort(key=lambda t: int(t[0]))
        except ValueError:
            rows.sort(key=lambda t: t[0].lower())
        for i, (_, k) in enumerate(rows):
            self._tree.move(k, "", i)

    # =========================================================================
    # HELPERS
    # =========================================================================

    def _set_range(self, a, b):
        self._v_p0.set(str(a))
        self._v_p1.set(str(b))

    def _status(self, msg: str):
        self._v_status.set(msg)

    def _err(self, msg: str):
        messagebox.showerror("Input Error", msg, parent=self)

    def _tick_clock(self):
        self._v_clock.set(datetime.now().strftime("%H:%M:%S"))
        self.after(1000, self._tick_clock)

    def _tick_elapsed(self):
        if self._active:
            secs = time.time() - self._t_start
            self._v_elapsed.set(f"⏱ {secs:.1f}s")
            self.after(300, self._tick_elapsed)


# =============================================================================
# ENTRY POINT
# =============================================================================

def main():
    app = NetProbeApp()
    app.mainloop()


if __name__ == "__main__":
    main()
