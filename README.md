# NetProbe — Port Scanner
### ST5062CEM · Programming and Algorithm 2

---

## Files

| File | Purpose |
|------|---------|
| `netprobe.py` | ✅ **RECOMMENDED** — Single self-contained app (GUI + logic in one file) |
| `port_scanner.py` | GUI-only file (imports from scanner_core.py) |
| `scanner_core.py` | Core scanning logic + custom data structures |
| `test_port_scanner.py` | 23 unit tests (all passing) |

---

## How to Run

### Option A — Single file (easiest):
```
python netprobe.py
```

### Option B — Two-file version:
```
python port_scanner.py
```
> Both `port_scanner.py` and `scanner_core.py` must be in the same folder.

---

## Run Unit Tests
```
python test_port_scanner.py
```

---

## Requirements
- Python 3.10+
- tkinter (standard library — see below if missing)

### Fix missing tkinter:
| OS | Command |
|----|---------|
| Windows | Reinstall Python → tick **"tcl/tk and IDLE"** |
| Ubuntu/Debian | `sudo apt install python3-tk` |
| macOS | `brew install python-tk` |

---

## Features
- Multi-threaded TCP port scanner (up to 500 threads)
- Custom singly-linked list data structure (insertion sort)
- Dark terminal-themed GUI (Tkinter)
- Sortable results table with colour-coded states
- Banner grabbing, open-only filter, quick port presets
- Export results to .txt
- Start / Stop scan at any time
- Live progress bar + elapsed timer

---

## Academic Notes
- Custom `ResultList` linked list with insertion sort (not Python's built-in list)
- Custom `ScanResult` value object
- Multi-threading with `Queue`, `threading.Event`, daemon threads
- Full docstrings and inline comments throughout
- APA 7th referencing in the accompanying report
