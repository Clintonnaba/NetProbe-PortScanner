"""
Unit Tests — Port Scanner (ST5062CEM CW1)
==========================================
Run with:  python -m pytest test_port_scanner.py -v
Or:        python test_port_scanner.py
"""

import unittest
from unittest.mock import patch, MagicMock
import socket

# Import the modules under test
from scanner_core import (
    ScanResult,
    ResultList,
    resolve_host,
    get_service_name,
    scan_port,
    grab_banner,
)


# ─────────────────────────────────────────────
# ScanResult Tests
# ─────────────────────────────────────────────

class TestScanResult(unittest.TestCase):

    def test_creation_open(self):
        r = ScanResult(80, "open", "HTTP", "Apache/2.4")
        self.assertEqual(r.port, 80)
        self.assertEqual(r.state, "open")
        self.assertEqual(r.service, "HTTP")
        self.assertEqual(r.banner, "Apache/2.4")

    def test_creation_closed(self):
        r = ScanResult(9999, "closed", "Unknown")
        self.assertEqual(r.state, "closed")
        self.assertEqual(r.banner, "")

    def test_repr(self):
        r = ScanResult(22, "open", "SSH")
        self.assertIn("22", repr(r))
        self.assertIn("open", repr(r))


# ─────────────────────────────────────────────
# ResultList (Custom Linked List) Tests
# ─────────────────────────────────────────────

class TestResultList(unittest.TestCase):

    def setUp(self):
        self.rl = ResultList()
        self.rl.append(ScanResult(443, "open",   "HTTPS"))
        self.rl.append(ScanResult(22,  "open",   "SSH"))
        self.rl.append(ScanResult(25,  "closed", "SMTP"))
        self.rl.append(ScanResult(80,  "open",   "HTTP"))

    def test_length(self):
        self.assertEqual(len(self.rl), 4)

    def test_sorted_output(self):
        """to_sorted_list should return results sorted ascending by port."""
        sorted_results = self.rl.to_sorted_list()
        ports = [r.port for r in sorted_results]
        self.assertEqual(ports, sorted(ports))

    def test_filter_open(self):
        """filter_open should only return open ports."""
        open_results = self.rl.filter_open()
        for r in open_results:
            self.assertEqual(r.state, "open")
        self.assertEqual(len(open_results), 3)

    def test_clear(self):
        self.rl.clear()
        self.assertEqual(len(self.rl), 0)
        self.assertEqual(self.rl.to_sorted_list(), [])

    def test_empty_list(self):
        empty = ResultList()
        self.assertEqual(len(empty), 0)
        self.assertEqual(empty.to_sorted_list(), [])
        self.assertEqual(empty.filter_open(), [])

    def test_insertion_sort_correctness(self):
        """Insertion sort inside to_sorted_list should handle reverse-order input."""
        rl = ResultList()
        for port in [1000, 500, 250, 1]:
            rl.append(ScanResult(port, "open", "Test"))
        sorted_ports = [r.port for r in rl.to_sorted_list()]
        self.assertEqual(sorted_ports, [1, 250, 500, 1000])


# ─────────────────────────────────────────────
# resolve_host Tests
# ─────────────────────────────────────────────

class TestResolveHost(unittest.TestCase):

    @patch("socket.gethostbyname", return_value="93.184.216.34")
    def test_resolves_hostname(self, _mock):
        ip = resolve_host("example.com")
        self.assertEqual(ip, "93.184.216.34")

    def test_resolves_ip_passthrough(self):
        """A plain IP address should resolve to itself."""
        ip = resolve_host("127.0.0.1")
        self.assertEqual(ip, "127.0.0.1")

    @patch("socket.gethostbyname", side_effect=socket.gaierror("Name not resolved"))
    def test_invalid_host_raises(self, _mock):
        with self.assertRaises(ValueError):
            resolve_host("this.host.does.not.exist.invalid")


# ─────────────────────────────────────────────
# get_service_name Tests
# ─────────────────────────────────────────────

class TestGetServiceName(unittest.TestCase):

    def test_known_ports(self):
        self.assertEqual(get_service_name(80),  "HTTP")
        self.assertEqual(get_service_name(22),  "SSH")
        self.assertEqual(get_service_name(443), "HTTPS")
        self.assertEqual(get_service_name(21),  "FTP")
        self.assertEqual(get_service_name(3306),"MySQL")

    @patch("socket.getservbyport", return_value="custom-svc")
    def test_socket_fallback(self, _mock):
        """Unknown ports should fall back to socket.getservbyport."""
        result = get_service_name(19999)
        self.assertEqual(result, "custom-svc")

    @patch("socket.getservbyport", side_effect=OSError)
    def test_totally_unknown_port(self, _mock):
        result = get_service_name(59999)
        self.assertEqual(result, "Unknown")


# ─────────────────────────────────────────────
# scan_port Tests (mocked networking)
# ─────────────────────────────────────────────

class TestScanPort(unittest.TestCase):

    @patch("socket.socket")
    def test_open_port(self, mock_socket_cls):
        """connect_ex returning 0 means the port is open."""
        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.connect_ex.return_value = 0
        mock_sock.recv.return_value = b""
        mock_socket_cls.return_value = mock_sock

        result = scan_port("127.0.0.1", 80, timeout=1.0, grab_banners=False)
        self.assertEqual(result.state, "open")
        self.assertEqual(result.port, 80)

    @patch("socket.socket")
    def test_closed_port(self, mock_socket_cls):
        """connect_ex returning non-zero means the port is closed."""
        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.connect_ex.return_value = 111  # ECONNREFUSED
        mock_socket_cls.return_value = mock_sock

        result = scan_port("127.0.0.1", 9999, timeout=1.0, grab_banners=False)
        self.assertEqual(result.state, "closed")

    @patch("socket.socket")
    def test_timeout_returns_filtered(self, mock_socket_cls):
        """A socket.timeout exception should yield 'filtered' state."""
        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.connect_ex.side_effect = socket.timeout
        mock_socket_cls.return_value = mock_sock

        result = scan_port("10.0.0.1", 80, timeout=0.1, grab_banners=False)
        self.assertEqual(result.state, "filtered")

    @patch("socket.socket")
    def test_banner_grabbed(self, mock_socket_cls):
        """When grab_banners=True and port is open, banner should be populated."""
        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.connect_ex.return_value = 0
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\n"
        mock_socket_cls.return_value = mock_sock

        result = scan_port("127.0.0.1", 22, timeout=1.0, grab_banners=True)
        self.assertEqual(result.state, "open")
        self.assertIn("SSH", result.banner)


# ─────────────────────────────────────────────
# grab_banner Tests
# ─────────────────────────────────────────────

class TestGrabBanner(unittest.TestCase):

    def test_returns_first_line(self):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"220 smtp.example.com ESMTP\r\nsome second line"
        banner = grab_banner(mock_sock, timeout=0.5)
        self.assertEqual(banner, "220 smtp.example.com ESMTP")

    def test_empty_banner(self):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b""
        banner = grab_banner(mock_sock)
        self.assertEqual(banner, "")

    def test_exception_returns_empty(self):
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = OSError("connection reset")
        banner = grab_banner(mock_sock)
        self.assertEqual(banner, "")

    def test_long_banner_truncated(self):
        mock_sock = MagicMock()
        long_line = b"A" * 200 + b"\r\n"
        mock_sock.recv.return_value = long_line
        banner = grab_banner(mock_sock)
        self.assertLessEqual(len(banner), 80)


# ─────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)
