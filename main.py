from __future__ import annotations

import argparse
import ipaddress
import json
import shutil
import subprocess
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_OUTPUTS = {
    "txt_path": "rules/ads.txt",
    "mrs_path": "rules/ads.mrs",
    "metadata_path": "rules/metadata.json",
}
DEFAULT_WHITELIST_PATH = "whitelist.txt"
SUPPORTED_SOURCE_TYPES = {"adguard", "clash-yaml", "hosts"}
COMMENT_PREFIXES = ("!", "[")
COSMETIC_MARKERS = ("##", "#@#", "#?#", "#$#")
SEPARATORS = "^/$:?&="
HOST_ALLOWED_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-*.")
ADBLOCK_HOSTS_REDIRECT_IPS = {"0.0.0.0", "127.0.0.1", "::1"}


@dataclass
class SourceStats:
    name: str
    type: str
    url: str
    fetched_bytes: int = 0
    added_rules: int = 0
    skipped_lines: int = 0
    sample_rules: list[str] = field(default_factory=list)
    sample_skips: list[str] = field(default_factory=list)

    def remember_rule(self, value: str) -> None:
        if len(self.sample_rules) < 5:
            self.sample_rules.append(value)

    def remember_skip(self, value: str) -> None:
        if len(self.sample_skips) < 5:
            self.sample_skips.append(value)


@dataclass(frozen=True)
class DomainRule:
    kind: str
    value: str


def fetch_text(url: str) -> tuple[str, int]:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "MihomoADRules/1.0 (+https://github.com/)",
            "Accept": "*/*",
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        body = response.read()
    return body.decode("utf-8", errors="replace"), len(body)


def strip_inline_comment(text: str) -> str:
    result: list[str] = []
    in_single = False
    in_double = False
    for char in text:
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == "#" and not in_single and not in_double:
            break
        result.append(char)
    return "".join(result).rstrip()


def unquote_yaml_scalar(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def parse_simple_mapping_yaml(text: str) -> dict:
    root: dict = {}
    stack: list[tuple[int, dict]] = [(-1, root)]

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        if not raw_line.strip():
            continue
        stripped = raw_line.lstrip(" ")
        if stripped.startswith("#"):
            continue
        indent = len(raw_line) - len(stripped)
        content = strip_inline_comment(stripped)
        if not content:
            continue
        if ":" not in content:
            raise ValueError(f"invalid YAML mapping at line {line_number}: {raw_line}")
        key, raw_value = content.split(":", 1)
        key = unquote_yaml_scalar(key.strip())
        value = raw_value.strip()

        while stack and indent <= stack[-1][0]:
            stack.pop()
        if not stack:
            raise ValueError(f"invalid indentation at line {line_number}: {raw_line}")
        container = stack[-1][1]

        if value:
            container[key] = unquote_yaml_scalar(value)
        else:
            child: dict = {}
            container[key] = child
            stack.append((indent, child))

    return root


def parse_simple_payload_yaml(text: str) -> list[str]:
    payload: list[str] = []
    in_payload = False
    payload_indent = 0

    for raw_line in text.splitlines():
        if not raw_line.strip():
            continue
        stripped = raw_line.lstrip(" ")
        if stripped.startswith("#"):
            continue
        indent = len(raw_line) - len(stripped)
        content = strip_inline_comment(stripped)
        if not content:
            continue

        if not in_payload:
            if content == "payload:":
                in_payload = True
                payload_indent = indent
            continue

        if indent <= payload_indent and not content.startswith("- "):
            break
        if content.startswith("- "):
            payload.append(unquote_yaml_scalar(content[2:].strip()))

    if in_payload:
        return payload
    raise ValueError("not a payload list YAML")


def load_config(path: Path) -> dict:
    data = parse_simple_mapping_yaml(path.read_text(encoding="utf-8"))
    rules = data.get("rules")
    if not isinstance(rules, dict) or not rules:
        raise ValueError("config.yaml must contain a non-empty rules mapping")
    outputs = dict(DEFAULT_OUTPUTS)
    raw_outputs = data.get("output") or {}
    if raw_outputs:
        if not isinstance(raw_outputs, dict):
            raise ValueError("output must be a YAML mapping")
        for key, value in raw_outputs.items():
            if key in outputs and value:
                outputs[key] = str(value)
    data["output"] = outputs
    return data


def split_host_candidate(text: str) -> tuple[str, str]:
    chars: list[str] = []
    for index, char in enumerate(text):
        if char in SEPARATORS:
            return "".join(chars).strip(), text[index:]
        chars.append(char)
    return "".join(chars).strip(), ""


def is_pure_domain_rule_remainder(remainder: str) -> bool:
    return remainder in {"", "^"}


def is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def is_host_like(candidate: str) -> bool:
    lowered = candidate.lower()
    if not lowered or "." not in lowered:
        return False
    if any(char not in HOST_ALLOWED_CHARS for char in lowered):
        return False
    trimmed = lowered.strip(".").strip()
    if not trimmed or "." not in trimmed or ".." in trimmed:
        return False
    if "*" in trimmed:
        return False
    labels = trimmed.split(".")
    if any(not label for label in labels):
        return False
    if not any(char.isalpha() for char in labels[-1]):
        return False
    return True


def normalize_suffix_candidate(candidate: str) -> str | None:
    trimmed = candidate.lower().strip().strip("*").strip(".")
    if not is_host_like(trimmed):
        return None
    return f"+.{trimmed}"


def normalize_exact_candidate(candidate: str) -> str | None:
    trimmed = candidate.lower().strip(".").strip()
    if not trimmed or "*" in trimmed or not is_host_like(trimmed):
        return None
    return trimmed


def strip_hosts_comment(line: str) -> str:
    if "#" not in line:
        return line.strip()
    return line.split("#", 1)[0].strip()


def parse_hosts_line(line: str, *, adblock_mode: bool = False) -> list[str]:
    stripped = strip_hosts_comment(line)
    if not stripped:
        return []
    parts = stripped.split()
    if len(parts) < 2:
        return []

    ip_token = parts[0]
    if not is_ip_literal(ip_token):
        return []
    if adblock_mode and ip_token not in ADBLOCK_HOSTS_REDIRECT_IPS:
        return []

    rules: list[str] = []
    for host in parts[1:]:
        if is_ip_literal(host):
            continue
        normalized = normalize_exact_candidate(host)
        if normalized:
            rules.append(normalized)
    return rules


def parse_adguard_line(line: str) -> str | None:
    value = line.strip()
    if not value or value.startswith(COMMENT_PREFIXES):
        return None
    if value.startswith("@@"):
        return None
    if any(marker in value for marker in COSMETIC_MARKERS):
        return None
    if value.startswith("/") and value.endswith("/"):
        return None
    if value.startswith("#"):
        return None
    if "$" in value:
        return None

    if value.startswith("||"):
        candidate, remainder = split_host_candidate(value[2:])
        if not is_pure_domain_rule_remainder(remainder):
            return None
        return normalize_suffix_candidate(candidate)

    if value.startswith("|http://") or value.startswith("|https://"):
        scheme_index = value.find("://")
        remainder = value[scheme_index + 3 :]
        candidate, tail = split_host_candidate(remainder)
        if not is_pure_domain_rule_remainder(tail):
            return None
        if "*" in candidate:
            return normalize_suffix_candidate(candidate)
        return normalize_exact_candidate(candidate)

    if value.startswith("|"):
        candidate, remainder = split_host_candidate(value[1:])
        if not is_pure_domain_rule_remainder(remainder):
            return None
        if "*" in candidate:
            return normalize_suffix_candidate(candidate)
        return normalize_exact_candidate(candidate)

    if value.startswith("/"):
        return None

    if "*" in value and not any(separator in value for separator in SEPARATORS):
        candidate, remainder = split_host_candidate(value)
        if remainder:
            return None
        return normalize_suffix_candidate(candidate)

    return None


def parse_adguard_rules(line: str) -> list[str]:
    normalized = parse_adguard_line(line)
    if normalized:
        return [normalized]
    return []


def should_record_skip_sample(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    if stripped.startswith(COMMENT_PREFIXES) or stripped.startswith("#"):
        return False
    return True


def normalize_payload_entry(entry: str) -> str | None:
    value = entry.strip().strip("\"'")
    if not value or value.startswith("#"):
        return None
    upper_value = value.upper()
    if upper_value.startswith("DOMAIN-SUFFIX,"):
        return normalize_suffix_candidate(value.split(",", 1)[1].strip())
    if upper_value.startswith("DOMAIN,"):
        return normalize_exact_candidate(value.split(",", 1)[1].strip())
    if upper_value.startswith("DOMAIN-KEYWORD,"):
        return None
    if value.startswith("+."):
        return normalize_suffix_candidate(value[2:])
    if value.startswith("*."):
        return normalize_suffix_candidate(value[2:])
    if value.startswith("."):
        return normalize_suffix_candidate(value[1:])
    if "*" in value:
        return normalize_suffix_candidate(value)
    return normalize_exact_candidate(value)


def parse_domain_rule(rule: str) -> DomainRule | None:
    normalized = normalize_payload_entry(rule)
    if not normalized:
        return None
    if normalized.startswith("+."):
        return DomainRule(kind="suffix", value=normalized[2:])
    return DomainRule(kind="exact", value=normalized)


def rule_matches_host(rule: DomainRule, host: str) -> bool:
    if rule.kind == "exact":
        return host == rule.value
    return host == rule.value or host.endswith(f".{rule.value}")


def rules_intersect(left: DomainRule, right: DomainRule) -> bool:
    if left.kind == "exact" and right.kind == "exact":
        return left.value == right.value
    if left.kind == "exact":
        return rule_matches_host(right, left.value)
    if right.kind == "exact":
        return rule_matches_host(left, right.value)
    return (
        left.value == right.value
        or left.value.endswith(f".{right.value}")
        or right.value.endswith(f".{left.value}")
    )


def load_whitelist(path: Path) -> tuple[list[str], dict]:
    if not path.exists():
        return [], {"path": str(path.as_posix()), "exists": False, "total_rules": 0, "invalid_lines": 0}

    whitelist_rules: set[str] = set()
    invalid_lines = 0
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        normalized = normalize_payload_entry(stripped)
        if normalized:
            whitelist_rules.add(normalized)
        else:
            invalid_lines += 1

    return sorted(whitelist_rules), {
        "path": str(path.as_posix()),
        "exists": True,
        "total_rules": len(whitelist_rules),
        "invalid_lines": invalid_lines,
    }


def apply_whitelist(blacklist: list[str], whitelist: list[str]) -> list[str]:
    if not whitelist:
        return list(blacklist)

    whitelist_rules = [rule for item in whitelist if (rule := parse_domain_rule(item))]
    filtered: list[str] = []
    for item in blacklist:
        black_rule = parse_domain_rule(item)
        if black_rule and any(rules_intersect(black_rule, white_rule) for white_rule in whitelist_rules):
            continue
        filtered.append(item)
    return filtered


def parse_clash_yaml_text(text: str) -> list[str]:
    result: list[str] = []
    for entry in parse_simple_payload_yaml(text):
        normalized = normalize_payload_entry(entry)
        if normalized:
            result.append(normalized)
    return result


def parse_clash_lines(text: str) -> list[str]:
    result: list[str] = []
    for raw_line in text.splitlines():
        normalized = normalize_payload_entry(raw_line)
        if normalized:
            result.append(normalized)
    return result


def collect_source_rules(source_type: str, text: str, stat: SourceStats) -> set[str]:
    collected: set[str] = set()

    if source_type == "adguard":
        for raw_line in text.splitlines():
            normalized_rules = parse_adguard_rules(raw_line)
            if normalized_rules:
                for normalized in normalized_rules:
                    collected.add(normalized)
                    stat.remember_rule(normalized)
            else:
                stripped = raw_line.strip()
                if stripped:
                    stat.skipped_lines += 1
                    if should_record_skip_sample(stripped):
                        stat.remember_skip(stripped)
        return collected

    if source_type == "hosts":
        for raw_line in text.splitlines():
            normalized_rules = parse_hosts_line(raw_line, adblock_mode=False)
            if normalized_rules:
                for normalized in normalized_rules:
                    collected.add(normalized)
                    stat.remember_rule(normalized)
            else:
                stripped = raw_line.strip()
                if stripped:
                    stat.skipped_lines += 1
                    if should_record_skip_sample(stripped):
                        stat.remember_skip(stripped)
        return collected

    try:
        parsed_rules = parse_clash_yaml_text(text)
    except Exception:
        parsed_rules = parse_clash_lines(text)
    for normalized in parsed_rules:
        collected.add(normalized)
        stat.remember_rule(normalized)
    return collected


def collect_rules(config_path: Path, whitelist_path: Path) -> tuple[dict, list[str]]:
    config = load_config(config_path)
    merged_rules: set[str] = set()
    stats: list[SourceStats] = []

    for name, source in config["rules"].items():
        if not isinstance(source, dict):
            raise ValueError(f"rule source {name} must be a YAML mapping")
        source_type = str(source.get("type", "")).strip()
        source_url = str(source.get("url", "")).strip()
        if source_type not in SUPPORTED_SOURCE_TYPES:
            raise ValueError(f"unsupported source type for {name}: {source_type}")
        if not source_url:
            raise ValueError(f"rule source {name} is missing url")

        stat = SourceStats(name=name, type=source_type, url=source_url)
        text, stat.fetched_bytes = fetch_text(source_url)
        before = len(merged_rules)
        merged_rules.update(collect_source_rules(source_type, text, stat))
        stat.added_rules = len(merged_rules) - before
        stats.append(stat)

    ordered_rules = sorted(
        merged_rules,
        key=lambda item: (
            item[2:] if item.startswith("+.") else item,
            0 if not item.startswith("+.") else 1,
            item,
        ),
    )
    whitelist_rules, whitelist_meta = load_whitelist(whitelist_path)
    filtered_rules = apply_whitelist(ordered_rules, whitelist_rules)

    metadata = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "config_path": str(config_path.as_posix()),
        "whitelist": {
            **whitelist_meta,
            "applied_rules": len(whitelist_rules),
            "removed_blacklist_rules": len(ordered_rules) - len(filtered_rules),
        },
        "total_rules_before_whitelist": len(ordered_rules),
        "total_rules": len(filtered_rules),
        "sources": [
            {
                "name": stat.name,
                "type": stat.type,
                "url": stat.url,
                "fetched_bytes": stat.fetched_bytes,
                "added_rules": stat.added_rules,
                "skipped_lines": stat.skipped_lines,
                "sample_rules": stat.sample_rules,
                "sample_skips": stat.sample_skips,
            }
            for stat in stats
        ],
    }
    return metadata, filtered_rules


def write_outputs(config_path: Path, metadata: dict, rules: list[str]) -> dict[str, Path]:
    outputs = load_config(config_path)["output"]
    txt_path = Path(outputs["txt_path"])
    mrs_path = Path(outputs["mrs_path"])
    metadata_path = Path(outputs["metadata_path"])

    for path in (txt_path, mrs_path, metadata_path):
        path.parent.mkdir(parents=True, exist_ok=True)

    txt_path.write_text("\n".join(rules) + "\n", encoding="utf-8")
    metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {
        "txt_path": txt_path,
        "mrs_path": mrs_path,
        "metadata_path": metadata_path,
    }


def convert_to_mrs(txt_path: Path, mrs_path: Path, mihomo_binary: str | None) -> bool:
    binary = mihomo_binary or shutil.which("mihomo")
    if not binary:
        return False
    subprocess.run(
        [binary, "convert-ruleset", "domain", "text", str(txt_path), str(mrs_path)],
        check=True,
    )
    return True


def build(config_path: Path, mihomo_binary: str | None, whitelist_path: Path) -> int:
    metadata, rules = collect_rules(config_path, whitelist_path)
    output_paths = write_outputs(config_path, metadata, rules)
    converted = convert_to_mrs(output_paths["txt_path"], output_paths["mrs_path"], mihomo_binary)
    summary = {
        "txt_path": str(output_paths["txt_path"].as_posix()),
        "mrs_path": str(output_paths["mrs_path"].as_posix()),
        "metadata_path": str(output_paths["metadata_path"].as_posix()),
        "total_rules": len(rules),
        "whitelist_path": str(whitelist_path.as_posix()),
        "whitelist_rules": metadata["whitelist"]["applied_rules"],
        "sources": {item["name"]: item["added_rules"] for item in metadata["sources"]},
        "mrs_converted": converted,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build Mihomo MRS rules from adguard/clash-yaml/hosts sources")
    parser.add_argument("--config", default="config.yaml", help="config file path")
    parser.add_argument(
        "--mihomo-binary",
        default=None,
        help="mihomo executable path; if omitted, mrs is generated only when mihomo exists in PATH",
    )
    parser.add_argument(
        "--whitelist",
        default=DEFAULT_WHITELIST_PATH,
        help="whitelist file path; supports DOMAIN / DOMAIN-SUFFIX / +.domain / domain",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    return build(Path(args.config), args.mihomo_binary, Path(args.whitelist))


if __name__ == "__main__":
    raise SystemExit(main())
