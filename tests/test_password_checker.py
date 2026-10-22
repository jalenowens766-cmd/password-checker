import hashlib
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

import requests

import password_checker as checker


class StrengthTests(unittest.TestCase):
    def test_empty_password(self):
        self.assertEqual(checker.estimate_entropy(""), 0)
        self.assertEqual(checker.check_strength("")[0], 0)

    def test_common_password_overrides_complexity(self):
        self.assertEqual(checker.check_strength("Passw0rd")[0], 0)

    def test_length_thresholds(self):
        scores = [checker.check_strength(value)[0] for value in
                  ("Az7!mQ2", "Az7!mQ2?", "Az7!mQ2?vL9#")]
        self.assertLess(scores[0], scores[1])
        self.assertLess(scores[1], scores[2])
        self.assertTrue(all(0 <= score <= 5 for score in scores))


class BreachTests(unittest.TestCase):
    def setUp(self):
        self.password = "Fabricated-test-input!42"
        self.digest = hashlib.sha1(self.password.encode()).hexdigest().upper()

    @patch("password_checker.requests.get")
    def test_only_prefix_sent_and_match_count_returned(self, get):
        response = Mock(text=f"{'0' * 35}:0\r\n{self.digest[5:]}:42\r\n")
        get.return_value = response
        self.assertEqual(checker.check_pwned(self.password), 42)
        get.assert_called_once_with(
            checker.HIBP_RANGE_URL.format(prefix=self.digest[:5]),
            headers={"User-Agent": "password-checker-portfolio-project", "Add-Padding": "true"},
            timeout=10,
        )
        response.raise_for_status.assert_called_once_with()

    @patch("password_checker.requests.get")
    def test_missing_suffix_returns_zero(self, get):
        get.return_value = Mock(text=f"{'0' * 35}:12\r\n")
        self.assertEqual(checker.check_pwned(self.password), 0)

    @patch("password_checker.requests.get")
    def test_padding_match_is_not_a_breach(self, get):
        get.return_value = Mock(text=f"{self.digest[5:]}:0\r\n")
        self.assertEqual(checker.check_pwned(self.password), 0)

    @patch("password_checker.requests.get")
    def test_http_errors_propagate(self, get):
        get.return_value.raise_for_status.side_effect = requests.HTTPError("503")
        with self.assertRaises(requests.HTTPError):
            checker.check_pwned(self.password)

    @patch("password_checker.sys.stdin.isatty", return_value=False)
    @patch("builtins.input", return_value="Fabricated-test-input!42")
    @patch("password_checker.requests.get", side_effect=requests.Timeout("timeout"))
    def test_network_failure_does_not_claim_password_is_clear(self, *_mocks):
        output = io.StringIO()
        with redirect_stdout(output):
            checker.main()
        self.assertIn("Could not reach HIBP", output.getvalue())
        self.assertNotIn("Not found", output.getvalue())
        self.assertNotIn("Fabricated-test-input!42", output.getvalue())


if __name__ == "__main__":
    unittest.main()
