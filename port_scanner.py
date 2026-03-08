"""
port_scanner.py — NetProbe GUI
================================
Module: ST5062CEM - Programming and Algorithm 2
Author: [Your Name]
Date:   March 2026

Entry point for the NetProbe port scanner application.
All scanning logic lives in scanner_core.py; this file owns the GUI.

Run:
    python port_scanner.py
"""

import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime

from scanner_core import (
    ScanResult,
    ResultList,
    PortScanner,
    resolve_host,
)

# ─────────────────────────────────────────────
# COLOUR PALETTE & FONTS
# ─────────────────────────────────────────────
BG       = "#0d1117"
PANEL    = "#161b22"
BORDER   = "#30363d"
GREEN    = "#39d353"
RED      = "#f85149"
YELLOW   = "#e3b341"
FG       = "#e6edf3"
FG_DIM   = "#8b949e"

MONO    = ("Courier New", 10)
MONO_SM = ("Courier New", 9)
SANS    = ("Segoe UI", 10)
SANS_SM = ("Segoe UI", 9)


class ToolTip:
    """Lightweight hover tooltip for any Tkinter widget."""

    def __init__(self, widget, text):
        self._widget = widget
        self._text = text
        self._tip_window = None
        widget.bind("<Enter>", self._show)
        widget.bind("<Leave>", self._hide)

    def _show(self, _event=None):
        x = self._widget.winfo_rootx() + 20
        y = self._widget.winfo_rooty() + 20
        self._tip_window = tw = tk.Toplevel(self._widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        tk.Label(tw, text=self._text, background="#21262d",
                 foreground=FG_DIM, relief="flat",
                 font=SANS_SM, padx=6, pady=4).pack()

    def _hide(self, _event=None):
        if self._tip_window:
            self._tip_window.destroy()
            self._tip_window = None


class PortScannerApp(tk.Tk):
    """NetProbe — main GUI window."""

    def __init__(self):
        super().__init__()
        self.title("NetProbe — Port Scanner")
        self.geometry("980x720")
        self.minsize(820, 580)
        self.configure(bg=BG)
        self._scanner = None
        self._scan_active = False
        self._scan_start_wall = 0.0
        self._results_store = ResultList()
        self._build_ui()
        self._apply_ttk_styles()

    def _apply_ttk_styles(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure("Scan.Horizontal.TProgressbar",
                    troughcolor=PANEL, background=GREEN,
                    bordercolor=BORDER, darkcolor=GREEN, lightcolor=GREEN)
        s.configure("Results.Treeview",
                    background=PANEL, foreground=FG,
                    fieldbackground=PANEL, rowheight=24,
                    font=MONO_SM, borderwidth=0)
        s.configure("Results.Treeview.Heading",
                    background=BORDER, foreground=FG,
                    font=("Segoe UI", 9, "bold"), relief="flat")
        s.map("Results.Treeview",
              background=[("selected", "#264f78")],
              foreground=[("selected", FG)])
        s.configure("Dark.Vertical.TScrollbar",
                    troughcolor=PANEL, background=BORDER,
                    arrowcolor=FG_DIM, bordercolor=PANEL)

    def _build_ui(self):
        self._build_header()
        self._build_controls()
        self._build_progress_bar()
        self._build_results_panel()
        self._build_statusbar()

    def _build_header(self):
        hdr = tk.Frame(self, bg=PANEL, height=60)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="⬡  NetProbe", font=("Courier New", 18, "bold"),
                 fg=GREEN, bg=PANEL).pack(side="left", padx=20, pady=10)
        tk.Label(hdr, text="Port Scanner  ·  ST5062CEM",
                 font=SANS_SM, fg=FG_DIM, bg=PANEL).pack(side="left", pady=10)
        self._clock_var = tk.StringVar()
        tk.Label(hdr, textvariable=self._clock_var, font=MONO_SM,
                 fg=FG_DIM, bg=PANEL).pack(side="right", padx=20)
        self._tick_clock()
        tk.Frame(self, bg=GREEN, height=2).pack(fill="x")

    def _build_controls(self):
        ctrl = tk.Frame(self, bg=BG, padx=20, pady=12)
        ctrl.pack(fill="x")

        # Row 1 — target and port range
        row1 = tk.Frame(ctrl, bg=BG)
        row1.pack(fill="x", pady=(0, 8))
        self._lbl(row1, "Target Host / IP").pack(side="left")
        self._host_var = tk.StringVar(value="scanme.nmap.org")
        he = self._entry(row1, self._host_var, width=28)
        he.pack(side="left", padx=(6, 20))
        ToolTip(he, "Hostname or IPv4 address to scan")
        self._lbl(row1, "Start Port").pack(side="left")
        self._start_var = tk.StringVar(value="1")
        self._entry(row1, self._start_var, width=8).pack(side="left", padx=(6, 20))
        self._lbl(row1, "End Port").pack(side="left")
        self._end_var = tk.StringVar(value="1024")
        self._entry(row1, self._end_var, width=8).pack(side="left", padx=(6, 20))
        self._lbl(row1, "Quick:").pack(side="left")
        for label, s, e in [("Top 100", 1, 100), ("Common", 1, 1024), ("Extended", 1, 10000)]:
            tk.Button(row1, text=label, font=SANS_SM, bg=BORDER, fg=FG_DIM,
                      relief="flat", cursor="hand2", padx=6, pady=2,
                      command=lambda _s=s, _e=e: self._set_range(_s, _e)
                      ).pack(side="left", padx=2)

        # Row 2 — advanced options
        row2 = tk.Frame(ctrl, bg=BG)
        row2.pack(fill="x", pady=(0, 8))
        self._lbl(row2, "Threads").pack(side="left")
        self._threads_var = tk.StringVar(value="150")
        self._entry(row2, self._threads_var, width=6).pack(side="left", padx=(6, 20))
        self._lbl(row2, "Timeout (s)").pack(side="left")
        self._timeout_var = tk.StringVar(value="0.8")
        self._entry(row2, self._timeout_var, width=6).pack(side="left", padx=(6, 20))
        self._banner_var = tk.BooleanVar(value=False)
        tk.Checkbutton(row2, text="Grab service banners",
                       variable=self._banner_var, bg=BG, fg=FG_DIM,
                       selectcolor=PANEL, activebackground=BG,
                       activeforeground=FG, font=SANS_SM,
                       cursor="hand2").pack(side="left", padx=(0, 20))
        self._open_only_var = tk.BooleanVar(value=True)
        tk.Checkbutton(row2, text="Show open ports only",
                       variable=self._open_only_var, bg=BG, fg=FG_DIM,
                       selectcolor=PANEL, activebackground=BG,
                       activeforeground=FG, font=SANS_SM,
                       cursor="hand2").pack(side="left")

        # Row 3 — action buttons
        row3 = tk.Frame(ctrl, bg=BG)
        row3.pack(fill="x")
        self._start_btn = self._btn(row3, "▶  Start Scan", GREEN, "#0d1117", self._on_start)
        self._start_btn.pack(side="left", padx=(0, 10))
        self._stop_btn = self._btn(row3, "■  Stop", RED, "#0d1117", self._on_stop)
        self._stop_btn.pack(side="left", padx=(0, 10))
        self._stop_btn.config(state="disabled")
        self._btn(row3, "↓  Export TXT", BORDER, FG_DIM, self._on_export).pack(side="left")
        self._btn(row3, "✕  Clear", BORDER, FG_DIM, self._on_clear).pack(side="left", padx=(10, 0))
        self._elapsed_var = tk.StringVar(value="")
        tk.Label(row3, textvariable=self._elapsed_var, font=MONO_SM,
                 fg=GREEN, bg=BG).pack(side="right")

    def _build_progress_bar(self):
        pf = tk.Frame(self, bg=BG, padx=20, pady=2)
        pf.pack(fill="x")
        self._progress_var = tk.DoubleVar(value=0)
        ttk.Progressbar(pf, variable=self._progress_var, maximum=100,
                        style="Scan.Horizontal.TProgressbar").pack(fill="x")
        self._progress_label = tk.Label(pf, text="", font=SANS_SM, fg=FG_DIM, bg=BG)
        self._progress_label.pack(anchor="e")

    def _build_results_panel(self):
        rf = tk.Frame(self, bg=BG, padx=20, pady=6)
        rf.pack(fill="both", expand=True)
        rh = tk.Frame(rf, bg=BG)
        rh.pack(fill="x", pady=(0, 4))
        tk.Label(rh, text="SCAN RESULTS", font=("Courier New", 10, "bold"),
                 fg=GREEN, bg=BG).pack(side="left")
        self._result_count_var = tk.StringVar(value="")
        tk.Label(rh, textvariable=self._result_count_var, font=SANS_SM,
                 fg=FG_DIM, bg=BG).pack(side="right")
        cols = ("Port", "State", "Service", "Banner")
        self._tree = ttk.Treeview(rf, columns=cols, show="headings",
                                  style="Results.Treeview", selectmode="browse")
        for col, width in zip(cols, [70, 82, 130, 590]):
            self._tree.heading(col, text=col, command=lambda c=col: self._sort_tree(c))
            self._tree.column(col, width=width, anchor="w")
        sb = ttk.Scrollbar(rf, orient="vertical", command=self._tree.yview,
                           style="Dark.Vertical.TScrollbar")
        self._tree.configure(yscrollcommand=sb.set)
        self._tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self._tree.tag_configure("open",     background="#0d2318", foreground=GREEN)
        self._tree.tag_configure("closed",   background=PANEL,    foreground=FG_DIM)
        self._tree.tag_configure("filtered", background="#1c1708", foreground=YELLOW)

    def _build_statusbar(self):
        sb = tk.Frame(self, bg=PANEL, height=26)
        sb.pack(fill="x", side="bottom")
        sb.pack_propagate(False)
        tk.Frame(sb, bg=GREEN, width=3).pack(side="left", fill="y")
        self._status_var = tk.StringVar(value="Ready — enter a target and press Start Scan.")
        tk.Label(sb, textvariable=self._status_var, font=SANS_SM,
                 fg=FG_DIM, bg=PANEL, anchor="w").pack(side="left", padx=10, fill="x")

    # ── Widget factories ─────────────────────────────

    def _lbl(self, parent, text):
        return tk.Label(parent, text=text, font=SANS_SM, fg=FG_DIM, bg=BG)

    def _entry(self, parent, var, width=14):
        return tk.Entry(parent, textvariable=var, width=width,
                        bg=PANEL, fg=FG, insertbackground=GREEN,
                        relief="flat", font=SANS, highlightthickness=1,
                        highlightcolor=GREEN, highlightbackground=BORDER)

    def _btn(self, parent, text, bg, fg, cmd):
        return tk.Button(parent, text=text, command=cmd,
                         bg=bg, fg=fg, font=("Segoe UI", 10, "bold"),
                         relief="flat", cursor="hand2", padx=14, pady=6,
                         activebackground=bg, activeforeground=fg)

    # ── Action callbacks ──────────────────────────────

    def _on_start(self):
        host_raw = self._host_var.get().strip()
        if not host_raw:
            self._error("Please enter a target hostname or IP address.")
            return
        try:
            port_start = int(self._start_var.get())
            port_end   = int(self._end_var.get())
            timeout    = float(self._timeout_var.get())
            threads    = int(self._threads_var.get())
        except ValueError:
            self._error("Port range, timeout, and threads must be valid numbers.")
            return
        if not (1 <= port_start <= port_end <= 65535):
            self._error("Port range must be 1–65535 with start ≤ end.")
            return
        if not (1 <= threads <= 500):
            self._error("Threads must be between 1 and 500.")
            return
        if not (0.01 <= timeout <= 10):
            self._error("Timeout must be between 0.01 and 10 seconds.")
            return
        try:
            ip = resolve_host(host_raw)
        except ValueError as exc:
            self._error(str(exc))
            return

        self._on_clear(keep_settings=True)
        self._results_store.clear()
        self._scan_active = True
        self._start_btn.config(state="disabled")
        self._stop_btn.config(state="normal")
        self._elapsed_var.set("")
        self._progress_var.set(0)
        total = port_end - port_start + 1
        self._set_status(
            f"Scanning  {ip}  │  ports {port_start}–{port_end}  "
            f"│  {total:,} ports  │  {threads} threads")
        self._scan_start_wall = time.time()
        self._tick_elapsed()

        self._scanner = PortScanner(
            host=ip, port_start=port_start, port_end=port_end,
            timeout=timeout, threads=threads,
            grab_banners=self._banner_var.get(),
            progress_callback=self._cb_progress,
            result_callback=self._cb_result,
            done_callback=self._cb_done,
        )
        self._scanner.start()

    def _on_stop(self):
        if self._scanner:
            self._scanner.stop()
        self._scan_active = False
        self._set_status("Scan stopped by user.")
        self._start_btn.config(state="normal")
        self._stop_btn.config(state="disabled")

    def _on_export(self):
        items = self._tree.get_children()
        if not items:
            messagebox.showinfo("Export", "No results to export.", parent=self)
            return
        path = filedialog.asksaveasfilename(
            parent=self, defaultextension=".txt",
            filetypes=[("Text file", "*.txt"), ("All files", "*.*")],
            title="Save Scan Results")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"NetProbe Scan — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            fh.write(f"Target : {self._host_var.get()}\n")
            fh.write(f"Range  : {self._start_var.get()}–{self._end_var.get()}\n")
            fh.write("─" * 70 + "\n")
            fh.write(f"{'Port':<8}{'State':<10}{'Service':<16}Banner\n")
            fh.write("─" * 70 + "\n")
            for iid in items:
                v = self._tree.item(iid, "values")
                fh.write(f"{v[0]:<8}{v[1]:<10}{v[2]:<16}{v[3]}\n")
        self._set_status(f"Exported → {path}")

    def _on_clear(self, keep_settings=False):
        for row in self._tree.get_children():
            self._tree.delete(row)
        self._progress_var.set(0)
        self._progress_label.config(text="")
        self._result_count_var.set("")
        if not keep_settings:
            self._elapsed_var.set("")
            self._set_status("Ready.")

    # ── Scanner callbacks (background threads → main thread via after()) ──

    def _cb_progress(self, scanned, total):
        self.after(0, self._ui_progress, scanned, total)

    def _cb_result(self, result):
        if self._open_only_var.get() and result.state != "open":
            return
        self.after(0, self._ui_insert_row, result)

    def _cb_done(self, results, elapsed):
        open_count = len(results.filter_open())
        self.after(0, self._ui_finalize, results, elapsed, open_count)

    # ── UI updaters (main thread only) ───────────────

    def _ui_progress(self, scanned, total):
        pct = (scanned / total * 100) if total else 0
        self._progress_var.set(pct)
        self._progress_label.config(
            text=f"{scanned:,} / {total:,} ports scanned  ({pct:.1f}%)")

    def _ui_insert_row(self, result):
        values = (result.port, result.state.upper(), result.service, result.banner)
        self._tree.insert("", "end", values=values, tags=(result.state,))
        children = self._tree.get_children()
        if children:
            self._tree.see(children[-1])
        n = len(children)
        self._result_count_var.set(f"{n} row{'s' if n != 1 else ''}")

    def _ui_finalize(self, results, elapsed, open_count):
        self._scan_active = False
        self._results_store = results
        self._start_btn.config(state="normal")
        self._stop_btn.config(state="disabled")
        self._progress_var.set(100)
        mins, secs = divmod(elapsed, 60)
        time_str = f"{int(mins)}m {secs:.1f}s" if mins else f"{secs:.2f}s"
        self._elapsed_var.set(f"⏱ {time_str}")
        self._set_status(
            f"Scan complete  ·  {len(results):,} ports scanned  ·  "
            f"{open_count} open  ·  finished in {time_str}")

    # ── Table sorting ──────────────────────────────────

    def _sort_tree(self, col):
        rows = [(self._tree.set(k, col), k) for k in self._tree.get_children("")]
        try:
            rows.sort(key=lambda t: int(t[0]))
        except ValueError:
            rows.sort(key=lambda t: t[0].lower())
        for index, (_, k) in enumerate(rows):
            self._tree.move(k, "", index)

    # ── Helpers ───────────────────────────────────────

    def _set_range(self, start, end):
        self._start_var.set(str(start))
        self._end_var.set(str(end))

    def _set_status(self, msg):
        self._status_var.set(msg)

    def _error(self, msg):
        messagebox.showerror("Input Error", msg, parent=self)

    def _tick_clock(self):
        self._clock_var.set(datetime.now().strftime("%H:%M:%S"))
        self.after(1000, self._tick_clock)

    def _tick_elapsed(self):
        if self._scan_active:
            secs = time.time() - self._scan_start_wall
            self._elapsed_var.set(f"⏱ {secs:.1f}s")
            self.after(250, self._tick_elapsed)


def main():
    app = PortScannerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
