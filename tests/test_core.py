import unittest

import domain_security_scan as scanner


class CoreHelpersTest(unittest.TestCase):
    def test_version(self):
        self.assertEqual(scanner.__version__, "1.0.1")

    def test_normalize_domain_preserves_web_host(self):
        self.assertEqual(
            scanner.normalize_domain("https://WWW.Example.com/path"),
            "www.example.com",
        )

    def test_fallback_root_domain(self):
        self.assertEqual(
            scanner.fallback_root_domain("new.home.example.com"),
            "example.com",
        )

    def test_fallback_multilabel_suffix(self):
        self.assertEqual(
            scanner.fallback_root_domain("app.example.co.uk"),
            "example.co.uk",
        )

    def test_rejects_invalid_domain(self):
        with self.assertRaises(ValueError):
            scanner.normalize_domain("not a domain")


if __name__ == "__main__":
    unittest.main()
