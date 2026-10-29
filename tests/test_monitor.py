import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta
from nhqm_ssl_monitor import check_certificate


class Tests(unittest.TestCase):
    def test_invalid_inputs(self):
        for host in ("", "https://example.com", "example.com/path", "user@host"):
            with self.assertRaises(ValueError):
                check_certificate(host)
        with self.assertRaises(ValueError):
            check_certificate("example.com", port=0)
        with self.assertRaises(ValueError):
            check_certificate("example.com", warning_days=-1)

    def test_connection_failure(self):
        with patch("nhqm_ssl_monitor.core.socket.create_connection", side_effect=OSError("offline")):
            result = check_certificate("example.com")
        self.assertFalse(result.valid)
        self.assertTrue(result.warning)
        self.assertIn("offline", result.error)

    def test_verified_certificate(self):
        future = datetime.now(timezone.utc) + timedelta(days=80)
        cert = {"notAfter": future.strftime("%b %d %H:%M:%S %Y GMT"),
                "issuer": ((('commonName', 'Test CA'),),),
                "subject": ((('commonName', 'example.com'),),)}
        tls = MagicMock()
        tls.__enter__.return_value.getpeercert.return_value = cert
        sock = MagicMock()
        context = MagicMock()
        context.wrap_socket.return_value = tls
        with patch("nhqm_ssl_monitor.core.ssl.create_default_context", return_value=context), \
             patch("nhqm_ssl_monitor.core.socket.create_connection", return_value=sock):
            result = check_certificate("example.com")
        self.assertTrue(result.valid)
        self.assertFalse(result.warning)
        self.assertGreaterEqual(result.days_remaining, 78)
        self.assertEqual(result.issuer, "commonName=Test CA")
        self.assertIn("expires_at", result.to_dict())

    def test_warning(self):
        future = datetime.now(timezone.utc) + timedelta(days=5)
        cert = {"notAfter": future.strftime("%b %d %H:%M:%S %Y GMT")}
        tls = MagicMock()
        tls.__enter__.return_value.getpeercert.return_value = cert
        context = MagicMock()
        context.wrap_socket.return_value = tls
        with patch("nhqm_ssl_monitor.core.ssl.create_default_context", return_value=context), \
             patch("nhqm_ssl_monitor.core.socket.create_connection", return_value=MagicMock()):
            result = check_certificate("example.com", warning_days=10)
        self.assertTrue(result.warning)
        self.assertTrue(result.valid)


if __name__ == "__main__":
    unittest.main()
