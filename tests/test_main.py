import unittest

from main import normalize_payload_entry, parse_adguard_line


class ParseAdguardLineTests(unittest.TestCase):
    def test_parse_standard_suffix_rule(self) -> None:
        self.assertEqual(parse_adguard_line("||8le8le.com^"), "DOMAIN-SUFFIX,8le8le.com")

    def test_parse_wildcard_domain_rule(self) -> None:
        self.assertEqual(parse_adguard_line("*-ad.sm.cn*"), "DOMAIN-SUFFIX,-ad.sm.cn")

    def test_parse_exact_scheme_rule(self) -> None:
        self.assertEqual(
            parse_adguard_line("|https://img.example.com^"),
            "DOMAIN,img.example.com",
        )

    def test_skip_exception_and_cosmetic_rules(self) -> None:
        self.assertIsNone(parse_adguard_line("@@||white.example.com^"))
        self.assertIsNone(parse_adguard_line("example.com##.ad-slot"))

    def test_skip_url_substring_and_invalid_wildcard_rules(self) -> None:
        self.assertIsNone(parse_adguard_line("ads.controller.js"))
        self.assertIsNone(parse_adguard_line("-*-*-*-*.alpha^$script,third-party"))

    def test_skip_path_specific_rules(self) -> None:
        self.assertIsNone(parse_adguard_line("||zhulang.com/zlpv.php"))
        self.assertIsNone(parse_adguard_line("||zol.com.cn/cgimp/zc.js"))

    def test_skip_cosmetic_domain_rules(self) -> None:
        self.assertIsNone(parse_adguard_line("douyu.com##.summer_enter"))

    def test_skip_option_scoped_rules(self) -> None:
        self.assertIsNone(parse_adguard_line("||example.com^$third-party"))
        self.assertIsNone(parse_adguard_line("||example.com^$domain=foo.com"))


class NormalizePayloadEntryTests(unittest.TestCase):
    def test_normalize_provider_payload_suffix(self) -> None:
        self.assertEqual(
            normalize_payload_entry("+.ads.example.com"),
            "DOMAIN-SUFFIX,ads.example.com",
        )

    def test_normalize_classical_domain_rules(self) -> None:
        self.assertEqual(
            normalize_payload_entry("DOMAIN-SUFFIX, ads.example.com"),
            "DOMAIN-SUFFIX,ads.example.com",
        )
        self.assertEqual(
            normalize_payload_entry("DOMAIN, exact.example.com"),
            "DOMAIN,exact.example.com",
        )

    def test_skip_domain_keyword_rule(self) -> None:
        self.assertIsNone(normalize_payload_entry("DOMAIN-KEYWORD,ads"))


if __name__ == "__main__":
    unittest.main()
