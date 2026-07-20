import unittest

from main import (
    apply_whitelist,
    normalize_payload_entry,
    parse_adguard_line,
    should_record_skip_sample,
)


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


class SkipSampleTests(unittest.TestCase):
    def test_skip_comment_and_metadata_lines(self) -> None:
        self.assertFalse(should_record_skip_sample("[Adblock Plus 2.0]"))
        self.assertFalse(should_record_skip_sample("! Version: 202607201012"))

    def test_keep_meaningful_skipped_rule_lines(self) -> None:
        self.assertTrue(should_record_skip_sample("||example.com/z.js"))
        self.assertTrue(should_record_skip_sample("||example.com^$third-party"))


class ApplyWhitelistTests(unittest.TestCase):
    def test_suffix_whitelist_removes_matching_blacklist_rules(self) -> None:
        blacklist = [
            "DOMAIN-SUFFIX,example.com",
            "DOMAIN,foo.example.com",
            "DOMAIN-SUFFIX,foo.example.com",
            "DOMAIN-SUFFIX,other.com",
        ]
        whitelist = ["DOMAIN-SUFFIX,example.com"]
        self.assertEqual(apply_whitelist(blacklist, whitelist), ["DOMAIN-SUFFIX,other.com"])

    def test_empty_whitelist_keeps_blacklist(self) -> None:
        blacklist = ["DOMAIN-SUFFIX,example.com", "DOMAIN,foo.example.com"]
        self.assertEqual(apply_whitelist(blacklist, []), blacklist)

    def test_exact_whitelist_removes_intersecting_parent_suffix(self) -> None:
        blacklist = [
            "DOMAIN-SUFFIX,example.com",
            "DOMAIN-SUFFIX,other.com",
        ]
        whitelist = ["DOMAIN,foo.example.com"]
        self.assertEqual(apply_whitelist(blacklist, whitelist), ["DOMAIN-SUFFIX,other.com"])


if __name__ == "__main__":
    unittest.main()
