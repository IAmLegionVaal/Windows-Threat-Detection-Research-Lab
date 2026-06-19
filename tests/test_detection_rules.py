from __future__ import annotations

import json
import unittest
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "rules" / "windows"
POSITIVE_PATH = ROOT / "sample-data" / "positive-events.jsonl"
NEGATIVE_PATH = ROOT / "sample-data" / "negative-events.jsonl"


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_rules() -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for path in sorted(RULES_DIR.glob("*.yml")):
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        rule["_path"] = str(path.relative_to(ROOT))
        rules.append(rule)
    return rules


def value_matches(actual: Any, operator: str, expected: Any) -> bool:
    actual_text = "" if actual is None else str(actual).lower()
    if operator == "equals":
        return actual == expected or actual_text == str(expected).lower()
    if operator == "endswith":
        return actual_text.endswith(str(expected).lower())
    if operator == "contains":
        return str(expected).lower() in actual_text
    if operator == "contains_any":
        return any(str(item).lower() in actual_text for item in expected)
    raise ValueError(f"Unsupported operator: {operator}")


def rule_matches(rule: dict[str, Any], event: dict[str, Any]) -> bool:
    detection = rule.get("detection", {})
    condition = detection.get("condition")
    if condition != "selection":
        raise ValueError(f"Unsupported condition in {rule['_path']}: {condition}")

    selection = detection.get("selection", {})
    for raw_key, expected in selection.items():
        if "|" in raw_key:
            field, operator = raw_key.split("|", 1)
        else:
            field, operator = raw_key, "equals"
        if not value_matches(event.get(field), operator, expected):
            return False
    return True


class DetectionRuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rules = load_rules()
        cls.positive_events = load_jsonl(POSITIVE_PATH)
        cls.negative_events = load_jsonl(NEGATIVE_PATH)

    def test_rules_have_required_metadata(self) -> None:
        self.assertGreaterEqual(len(self.rules), 2)
        required = {"title", "id", "status", "description", "logsource", "detection", "level", "tags"}
        for rule in self.rules:
            self.assertTrue(required.issubset(rule), rule["_path"])
            self.assertIsInstance(rule["tags"], list)
            self.assertTrue(any(tag.startswith("attack.") for tag in rule["tags"]))

    def test_each_rule_matches_expected_positive_event(self) -> None:
        matched_rule_ids: set[str] = set()
        for event in self.positive_events:
            actual_matches = {rule["id"] for rule in self.rules if rule_matches(rule, event)}
            expected_matches = set(event.get("ExpectedRules", []))
            self.assertEqual(expected_matches, actual_matches, event)
            matched_rule_ids.update(actual_matches)
        self.assertEqual({rule["id"] for rule in self.rules}, matched_rule_ids)

    def test_negative_events_do_not_match(self) -> None:
        for event in self.negative_events:
            matches = [rule["id"] for rule in self.rules if rule_matches(rule, event)]
            self.assertEqual([], matches, event)


if __name__ == "__main__":
    unittest.main(verbosity=2)
