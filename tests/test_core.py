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


class ResultModelsTest(unittest.TestCase):
    def test_check_accepts_existing_string_values_and_serializes_identically(self):
        check = scanner.Check(
            "Mail",
            "SPF",
            "fail",
            "Missing SPF.",
            8,
            0,
            True,
        )

        self.assertEqual(check.category, "Mail")
        self.assertEqual(check.status, "fail")
        self.assertEqual(
            check.to_dict(),
            {
                "category": "Mail",
                "name": "SPF",
                "status": "fail",
                "message": "Missing SPF.",
                "weight": 8,
                "earned": 0,
                "applicable": True,
            },
        )

    def test_check_rejects_unknown_status(self):
        with self.assertRaises(ValueError):
            scanner.Check("Mail", "SPF", "invalid", "Bad status")

    def test_check_rejects_unknown_category(self):
        with self.assertRaises(ValueError):
            scanner.Check("Unknown", "Example", "info", "Bad category")

    def test_score_public_shape_is_unchanged(self):
        instance = scanner.Scanner("example.com")
        instance.add_check("Web", "One", "pass", "ok", 2, 2)
        instance.add_check("Web", "Two", "warn", "review", 2, 1)
        instance.add_check("Web", "Ignored", "unknown", "verify", 5, 0, False)

        self.assertEqual(
            instance.score(),
            {
                "score": 75,
                "label": "Good",
                "earned_points": 3,
                "possible_points": 4,
            },
        )

    def test_report_serializes_status_and_category_as_plain_strings(self):
        instance = scanner.Scanner("example.com")
        instance.add_check("Domain", "CAA", "pass", "ok", 3, 3)
        report = instance.to_dict()

        self.assertIs(type(report["checks"][0]["category"]), str)
        self.assertIs(type(report["checks"][0]["status"]), str)
        self.assertEqual(report["checks"][0]["category"], "Domain")
        self.assertEqual(report["checks"][0]["status"], "pass")


if __name__ == "__main__":
    unittest.main()
