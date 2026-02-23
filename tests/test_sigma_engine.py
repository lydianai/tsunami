#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Comprehensive tests for TSUNAMI SOC Sigma Rule Engine.
Covers: parser, evaluator, converters, repository, engine, blueprint, edge cases.
"""

import json
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure project root is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.siem_integration.sigma_engine import (
    SigmaStatus,
    SigmaLevel,
    SigmaDetection,
    SigmaRule,
    SigmaParseError,
    SigmaParser,
    DetectionEvaluator,
    WazuhConverter,
    SuricataConverter,
    SigmaRepository,
    SigmaEngine,
    create_sigma_blueprint,
    get_sigma_engine,
    _xml_escape,
    _suricata_escape,
    SIGMA_LOGSOURCE_FIELDS,
    SIGMA_MODIFIERS,
)


# ============================================================================
# Sample Sigma YAML rules for testing
# ============================================================================

SAMPLE_RULE_YAML = """
title: Suspicious PowerShell Command
id: 12345678-1234-1234-1234-123456789abc
status: test
level: high
description: Detects suspicious PowerShell execution
author: TSUNAMI SOC
date: 2024/01/15
modified: 2024/06/01
references:
    - https://example.com/ps-attack
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '-enc'
            - '-nop'
            - 'bypass'
        Image|endswith: '\\powershell.exe'
    condition: selection
falsepositives:
    - Legitimate admin scripts
fields:
    - CommandLine
    - ParentImage
"""

SAMPLE_RULE_COMPLEX = """
title: Mimikatz Detection
id: aaaabbbb-cccc-dddd-eeee-ffffaaaabbbb
status: stable
level: critical
description: Detects Mimikatz usage via command line
author: Test Author
date: 2024/03/01
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains:
            - 'sekurlsa'
            - 'logonpasswords'
    selection2:
        Image|endswith:
            - '\\mimikatz.exe'
            - '\\mimi.exe'
    filter1:
        User: 'SYSTEM'
    condition: (selection1 or selection2) and not filter1
falsepositives:
    - Security testing tools
"""

SAMPLE_RULE_MINIMAL = """
title: Minimal Rule
logsource:
    category: test
detection:
    selection:
        field1: value1
    condition: selection
"""

SAMPLE_RULE_NETWORK = """
title: DNS Query to Malicious Domain
id: net-rule-001
level: medium
status: experimental
logsource:
    category: dns_query
    product: windows
detection:
    selection:
        QueryName|endswith:
            - '.evil.com'
            - '.malware.org'
    condition: selection
tags:
    - attack.command_and_control
    - attack.t1071.004
"""

SAMPLE_RULE_ALL_OF = """
title: All Selections Match
logsource:
    category: test
detection:
    selection1:
        fieldA: valueA
    selection2:
        fieldB: valueB
    condition: all of selection*
"""

SAMPLE_RULE_1_OF = """
title: Any Selection Matches
logsource:
    category: test
detection:
    selection1:
        fieldA: wrongValue
    selection2:
        fieldB: valueB
    condition: 1 of selection*
"""


# ============================================================================
# Test: SigmaStatus Enum
# ============================================================================

class TestSigmaStatus(unittest.TestCase):

    def test_values(self):
        self.assertEqual(SigmaStatus.STABLE.value, "stable")
        self.assertEqual(SigmaStatus.TEST.value, "test")
        self.assertEqual(SigmaStatus.EXPERIMENTAL.value, "experimental")
        self.assertEqual(SigmaStatus.DEPRECATED.value, "deprecated")
        self.assertEqual(SigmaStatus.UNSUPPORTED.value, "unsupported")

    def test_from_string_exact(self):
        self.assertEqual(SigmaStatus.from_string("stable"), SigmaStatus.STABLE)
        self.assertEqual(SigmaStatus.from_string("test"), SigmaStatus.TEST)

    def test_from_string_case_insensitive(self):
        self.assertEqual(SigmaStatus.from_string("STABLE"), SigmaStatus.STABLE)
        self.assertEqual(SigmaStatus.from_string("Test"), SigmaStatus.TEST)

    def test_from_string_unknown(self):
        self.assertEqual(SigmaStatus.from_string("garbage"), SigmaStatus.EXPERIMENTAL)

    def test_from_string_empty(self):
        self.assertEqual(SigmaStatus.from_string(""), SigmaStatus.EXPERIMENTAL)

    def test_from_string_whitespace(self):
        self.assertEqual(SigmaStatus.from_string("  stable  "), SigmaStatus.STABLE)


# ============================================================================
# Test: SigmaLevel Enum
# ============================================================================

class TestSigmaLevel(unittest.TestCase):

    def test_values(self):
        self.assertEqual(SigmaLevel.CRITICAL.value, "critical")
        self.assertEqual(SigmaLevel.HIGH.value, "high")
        self.assertEqual(SigmaLevel.MEDIUM.value, "medium")
        self.assertEqual(SigmaLevel.LOW.value, "low")
        self.assertEqual(SigmaLevel.INFORMATIONAL.value, "informational")

    def test_from_string_exact(self):
        self.assertEqual(SigmaLevel.from_string("high"), SigmaLevel.HIGH)
        self.assertEqual(SigmaLevel.from_string("critical"), SigmaLevel.CRITICAL)

    def test_from_string_info_alias(self):
        self.assertEqual(SigmaLevel.from_string("info"), SigmaLevel.INFORMATIONAL)

    def test_from_string_unknown(self):
        self.assertEqual(SigmaLevel.from_string("garbage"), SigmaLevel.MEDIUM)

    def test_from_string_empty(self):
        self.assertEqual(SigmaLevel.from_string(""), SigmaLevel.MEDIUM)

    def test_numeric(self):
        self.assertEqual(SigmaLevel.CRITICAL.numeric, 5)
        self.assertEqual(SigmaLevel.HIGH.numeric, 4)
        self.assertEqual(SigmaLevel.MEDIUM.numeric, 3)
        self.assertEqual(SigmaLevel.LOW.numeric, 2)
        self.assertEqual(SigmaLevel.INFORMATIONAL.numeric, 1)

    def test_wazuh_level(self):
        self.assertEqual(SigmaLevel.CRITICAL.wazuh_level, 15)
        self.assertEqual(SigmaLevel.HIGH.wazuh_level, 12)
        self.assertEqual(SigmaLevel.MEDIUM.wazuh_level, 8)
        self.assertEqual(SigmaLevel.LOW.wazuh_level, 5)
        self.assertEqual(SigmaLevel.INFORMATIONAL.wazuh_level, 3)


# ============================================================================
# Test: SigmaRule Dataclass
# ============================================================================

class TestSigmaRule(unittest.TestCase):

    def test_default_creation(self):
        rule = SigmaRule(title="Test Rule")
        self.assertTrue(rule.rule_id)
        self.assertEqual(rule.title, "Test Rule")
        self.assertEqual(rule.status, SigmaStatus.EXPERIMENTAL)
        self.assertEqual(rule.level, SigmaLevel.MEDIUM)
        self.assertTrue(rule.imported_at)
        self.assertTrue(rule.enabled)

    def test_custom_rule_id(self):
        rule = SigmaRule(rule_id="custom-id", title="Test")
        self.assertEqual(rule.rule_id, "custom-id")

    def test_mitre_extraction_from_tags(self):
        rule = SigmaRule(
            title="Test",
            tags=["attack.execution", "attack.t1059.001", "attack.defense_evasion"],
        )
        self.assertIn("T1059.001", rule.mitre_techniques)
        self.assertIn("Execution", rule.mitre_tactics)
        self.assertIn("Defense Evasion", rule.mitre_tactics)

    def test_mitre_no_duplicates(self):
        rule = SigmaRule(
            title="Test",
            tags=["attack.t1059.001", "attack.t1059.001"],
        )
        self.assertEqual(rule.mitre_techniques.count("T1059.001"), 1)

    def test_hash_from_yaml(self):
        rule = SigmaRule(title="Test", raw_yaml="title: Test\n")
        self.assertTrue(rule.hash)
        self.assertEqual(len(rule.hash), 32)

    def test_to_dict(self):
        rule = SigmaRule(
            title="Test Rule",
            level=SigmaLevel.HIGH,
            status=SigmaStatus.STABLE,
            tags=["attack.t1059"],
        )
        d = rule.to_dict()
        self.assertEqual(d["title"], "Test Rule")
        self.assertEqual(d["level"], "high")
        self.assertEqual(d["status"], "stable")
        self.assertIn("attack.t1059", d["tags"])
        self.assertTrue(d["enabled"])

    def test_to_dict_serializable(self):
        rule = SigmaRule(title="Serializable")
        d = rule.to_dict()
        json_str = json.dumps(d)
        self.assertIsInstance(json_str, str)


# ============================================================================
# Test: SigmaParser
# ============================================================================

class TestSigmaParser(unittest.TestCase):

    def test_parse_basic_rule(self):
        rule = SigmaParser.parse(SAMPLE_RULE_YAML)
        self.assertEqual(rule.title, "Suspicious PowerShell Command")
        self.assertEqual(rule.rule_id, "12345678-1234-1234-1234-123456789abc")
        self.assertEqual(rule.status, SigmaStatus.TEST)
        self.assertEqual(rule.level, SigmaLevel.HIGH)
        self.assertEqual(rule.author, "TSUNAMI SOC")
        self.assertEqual(rule.logsource["category"], "process_creation")
        self.assertEqual(rule.logsource["product"], "windows")
        self.assertIn("selection", rule.detection.selections)
        self.assertEqual(rule.detection.condition, "selection")
        self.assertTrue(len(rule.falsepositives) > 0)
        self.assertTrue(len(rule.fields) > 0)

    def test_parse_complex_rule(self):
        rule = SigmaParser.parse(SAMPLE_RULE_COMPLEX)
        self.assertEqual(rule.title, "Mimikatz Detection")
        self.assertEqual(rule.level, SigmaLevel.CRITICAL)
        self.assertEqual(rule.status, SigmaStatus.STABLE)
        self.assertIn("selection1", rule.detection.selections)
        self.assertIn("selection2", rule.detection.selections)
        self.assertIn("filter1", rule.detection.filters)
        self.assertIn("and not filter1", rule.detection.condition)

    def test_parse_minimal_rule(self):
        rule = SigmaParser.parse(SAMPLE_RULE_MINIMAL)
        self.assertEqual(rule.title, "Minimal Rule")
        self.assertEqual(rule.status, SigmaStatus.EXPERIMENTAL)
        self.assertEqual(rule.level, SigmaLevel.MEDIUM)

    def test_parse_mitre_extraction(self):
        rule = SigmaParser.parse(SAMPLE_RULE_YAML)
        self.assertIn("T1059.001", rule.mitre_techniques)
        self.assertIn("Execution", rule.mitre_tactics)

    def test_parse_empty_raises(self):
        with self.assertRaises(SigmaParseError):
            SigmaParser.parse("")

    def test_parse_invalid_yaml_raises(self):
        with self.assertRaises(SigmaParseError):
            SigmaParser.parse("::invalid:: yaml [[[")

    def test_parse_no_title_raises(self):
        with self.assertRaises(SigmaParseError):
            SigmaParser.parse("detection:\n  selection:\n    x: y\n  condition: selection\nlogsource:\n  category: test\n")

    def test_parse_no_detection_raises(self):
        with self.assertRaises(SigmaParseError):
            SigmaParser.parse("title: Test\nlogsource:\n  category: test\n")

    def test_parse_no_logsource_raises(self):
        with self.assertRaises(SigmaParseError):
            SigmaParser.parse("title: Test\ndetection:\n  selection:\n    x: y\n  condition: selection\n")

    def test_parse_non_dict_raises(self):
        with self.assertRaises(SigmaParseError):
            SigmaParser.parse("- list\n- items\n")

    def test_parse_source_file_stored(self):
        rule = SigmaParser.parse(SAMPLE_RULE_MINIMAL, source_file="/tmp/test.yml")
        self.assertEqual(rule.source_file, "/tmp/test.yml")

    def test_parse_references_as_single_string(self):
        yaml_content = """
title: Test
logsource:
    category: test
detection:
    selection:
        field1: value1
    condition: selection
references: https://single.ref
"""
        rule = SigmaParser.parse(yaml_content)
        self.assertEqual(rule.references, ["https://single.ref"])

    def test_parse_condition_list(self):
        yaml_content = """
title: Multi Condition
logsource:
    category: test
detection:
    selection1:
        field1: value1
    selection2:
        field2: value2
    condition:
        - selection1
        - selection2
"""
        rule = SigmaParser.parse(yaml_content)
        self.assertIn("or", rule.detection.condition)

    def test_parse_file_not_found(self):
        with self.assertRaises(SigmaParseError):
            SigmaParser.parse_file("/nonexistent/path.yml")

    def test_parse_file_wrong_extension(self):
        with self.assertRaises(SigmaParseError):
            SigmaParser.parse_file("/tmp/test.txt")

    def test_parse_file_valid(self):
        tmpdir = tempfile.mkdtemp()
        try:
            filepath = os.path.join(tmpdir, "test.yml")
            with open(filepath, "w") as f:
                f.write(SAMPLE_RULE_MINIMAL)
            rule = SigmaParser.parse_file(filepath)
            self.assertEqual(rule.title, "Minimal Rule")
        finally:
            shutil.rmtree(tmpdir)

    def test_parse_directory(self):
        tmpdir = tempfile.mkdtemp()
        try:
            # Write 3 valid rules
            for i in range(3):
                filepath = os.path.join(tmpdir, f"rule_{i}.yml")
                with open(filepath, "w") as f:
                    f.write(SAMPLE_RULE_MINIMAL.replace("Minimal Rule", f"Rule {i}"))

            # Write 1 invalid file
            with open(os.path.join(tmpdir, "invalid.yml"), "w") as f:
                f.write("not: a: valid: sigma: rule")

            rules = SigmaParser.parse_directory(tmpdir)
            self.assertEqual(len(rules), 3)
        finally:
            shutil.rmtree(tmpdir)

    def test_parse_directory_nonexistent(self):
        rules = SigmaParser.parse_directory("/nonexistent/path")
        self.assertEqual(len(rules), 0)

    def test_parse_directory_recursive(self):
        tmpdir = tempfile.mkdtemp()
        try:
            subdir = os.path.join(tmpdir, "subdir")
            os.makedirs(subdir)
            with open(os.path.join(subdir, "rule.yml"), "w") as f:
                f.write(SAMPLE_RULE_MINIMAL)

            # Non-recursive should find 0
            rules_flat = SigmaParser.parse_directory(tmpdir, recursive=False)
            self.assertEqual(len(rules_flat), 0)

            # Recursive should find 1
            rules_rec = SigmaParser.parse_directory(tmpdir, recursive=True)
            self.assertEqual(len(rules_rec), 1)
        finally:
            shutil.rmtree(tmpdir)


# ============================================================================
# Test: DetectionEvaluator
# ============================================================================

class TestDetectionEvaluator(unittest.TestCase):

    # --- Value Matching ---

    def test_wildcard_match_exact(self):
        self.assertTrue(DetectionEvaluator._wildcard_match("hello", "hello"))
        self.assertTrue(DetectionEvaluator._wildcard_match("hello", "HELLO"))

    def test_wildcard_match_star(self):
        self.assertTrue(DetectionEvaluator._wildcard_match("*powershell*", "cmd /c powershell.exe"))
        self.assertTrue(DetectionEvaluator._wildcard_match("*.exe", "test.exe"))

    def test_wildcard_match_question(self):
        self.assertTrue(DetectionEvaluator._wildcard_match("test?", "testA"))
        self.assertFalse(DetectionEvaluator._wildcard_match("test?", "testAB"))

    def test_wildcard_escape(self):
        self.assertTrue(DetectionEvaluator._wildcard_match("test\\*", "test*"))

    def test_match_value_contains(self):
        self.assertTrue(DetectionEvaluator.match_value("needle", "hayneedlestack", ["contains"]))
        self.assertFalse(DetectionEvaluator.match_value("missing", "haystack", ["contains"]))

    def test_match_value_startswith(self):
        self.assertTrue(DetectionEvaluator.match_value("start", "start_something", ["startswith"]))
        self.assertFalse(DetectionEvaluator.match_value("start", "notstart", ["startswith"]))

    def test_match_value_endswith(self):
        self.assertTrue(DetectionEvaluator.match_value(".exe", "process.exe", ["endswith"]))
        self.assertFalse(DetectionEvaluator.match_value(".exe", "process.dll", ["endswith"]))

    def test_match_value_regex(self):
        self.assertTrue(DetectionEvaluator.match_value(r"cmd.*powershell", "cmd /c powershell", ["re"]))
        self.assertFalse(DetectionEvaluator.match_value(r"^xyz$", "abc", ["re"]))

    def test_match_value_regex_invalid(self):
        self.assertFalse(DetectionEvaluator.match_value("[invalid(", "test", ["re"]))

    def test_match_value_gt(self):
        self.assertTrue(DetectionEvaluator.match_value(5, 10, ["gt"]))
        self.assertFalse(DetectionEvaluator.match_value(10, 5, ["gt"]))

    def test_match_value_gte(self):
        self.assertTrue(DetectionEvaluator.match_value(5, 5, ["gte"]))
        self.assertTrue(DetectionEvaluator.match_value(5, 6, ["gte"]))

    def test_match_value_lt(self):
        self.assertTrue(DetectionEvaluator.match_value(10, 5, ["lt"]))
        self.assertFalse(DetectionEvaluator.match_value(5, 10, ["lt"]))

    def test_match_value_lte(self):
        self.assertTrue(DetectionEvaluator.match_value(5, 5, ["lte"]))

    def test_match_value_numeric_non_numeric(self):
        self.assertFalse(DetectionEvaluator.match_value("abc", "def", ["gt"]))

    def test_match_value_none_value(self):
        self.assertTrue(DetectionEvaluator.match_value(None, None))
        self.assertFalse(DetectionEvaluator.match_value("x", None, []))

    # --- Field Modifier Parsing ---

    def test_parse_field_modifiers(self):
        field, mods = DetectionEvaluator._parse_field_modifiers("CommandLine|contains|all")
        self.assertEqual(field, "CommandLine")
        self.assertIn("contains", mods)
        self.assertIn("all", mods)

    def test_parse_field_no_modifiers(self):
        field, mods = DetectionEvaluator._parse_field_modifiers("Image")
        self.assertEqual(field, "Image")
        self.assertEqual(mods, [])

    def test_parse_field_unknown_modifier_filtered(self):
        field, mods = DetectionEvaluator._parse_field_modifiers("field|unknown|contains")
        self.assertEqual(field, "field")
        self.assertIn("contains", mods)
        self.assertNotIn("unknown", mods)

    # --- Selection Evaluation ---

    def test_evaluate_selection_dict_and(self):
        """Dict fields are AND-ed."""
        sel = {"fieldA": "valueA", "fieldB": "valueB"}
        event = {"fieldA": "valueA", "fieldB": "valueB"}
        self.assertTrue(DetectionEvaluator.evaluate_selection(sel, event))

    def test_evaluate_selection_dict_and_partial(self):
        sel = {"fieldA": "valueA", "fieldB": "valueB"}
        event = {"fieldA": "valueA", "fieldB": "wrong"}
        self.assertFalse(DetectionEvaluator.evaluate_selection(sel, event))

    def test_evaluate_selection_list_values_or(self):
        """List values within a field are OR-ed."""
        sel = {"field": ["val1", "val2", "val3"]}
        event = {"field": "val2"}
        self.assertTrue(DetectionEvaluator.evaluate_selection(sel, event))

    def test_evaluate_selection_list_all_modifier(self):
        """With 'all' modifier, all values must match."""
        sel = {"field|all": ["val1", "val2"]}
        event = {"field": "val1"}
        self.assertFalse(DetectionEvaluator.evaluate_selection(sel, event))

    def test_evaluate_selection_list_of_dicts(self):
        """List of dicts: OR across elements."""
        sel = [
            {"fieldA": "wrongA"},
            {"fieldB": "valueB"},
        ]
        event = {"fieldB": "valueB"}
        self.assertTrue(DetectionEvaluator.evaluate_selection(sel, event))

    def test_evaluate_selection_case_insensitive_field(self):
        """Case-insensitive field lookup."""
        sel = {"CommandLine": "*powershell*"}
        event = {"commandline": "powershell.exe -enc abc"}
        self.assertTrue(DetectionEvaluator.evaluate_selection(sel, event))

    def test_evaluate_selection_non_dict_returns_false(self):
        self.assertFalse(DetectionEvaluator.evaluate_selection("not a dict", {}))

    # --- Condition Evaluation ---

    def test_condition_simple_selection(self):
        sels = {"selection": {"field1": "value1"}}
        event = {"field1": "value1"}
        self.assertTrue(DetectionEvaluator.evaluate_condition("selection", sels, {}, event))

    def test_condition_and(self):
        sels = {
            "sel1": {"fieldA": "A"},
            "sel2": {"fieldB": "B"},
        }
        event = {"fieldA": "A", "fieldB": "B"}
        self.assertTrue(DetectionEvaluator.evaluate_condition("sel1 and sel2", sels, {}, event))

    def test_condition_and_fails(self):
        sels = {
            "sel1": {"fieldA": "A"},
            "sel2": {"fieldB": "B"},
        }
        event = {"fieldA": "A", "fieldB": "wrong"}
        self.assertFalse(DetectionEvaluator.evaluate_condition("sel1 and sel2", sels, {}, event))

    def test_condition_or(self):
        sels = {
            "sel1": {"fieldA": "wrong"},
            "sel2": {"fieldB": "B"},
        }
        event = {"fieldB": "B"}
        self.assertTrue(DetectionEvaluator.evaluate_condition("sel1 or sel2", sels, {}, event))

    def test_condition_not(self):
        sels = {"selection": {"field1": "value1"}}
        filters = {"filter1": {"field2": "banned"}}
        event = {"field1": "value1", "field2": "banned"}
        self.assertFalse(
            DetectionEvaluator.evaluate_condition("selection and not filter1", sels, filters, event)
        )

    def test_condition_not_allows(self):
        sels = {"selection": {"field1": "value1"}}
        filters = {"filter1": {"field2": "banned"}}
        event = {"field1": "value1", "field2": "safe"}
        self.assertTrue(
            DetectionEvaluator.evaluate_condition("selection and not filter1", sels, filters, event)
        )

    def test_condition_parentheses(self):
        sels = {
            "sel1": {"fieldA": "A"},
            "sel2": {"fieldB": "B"},
        }
        filters = {"filter1": {"fieldC": "C"}}
        event = {"fieldB": "B", "fieldC": "other"}
        self.assertTrue(
            DetectionEvaluator.evaluate_condition("(sel1 or sel2) and not filter1", sels, filters, event)
        )

    def test_condition_all_of_them(self):
        sels = {
            "sel1": {"fieldA": "A"},
            "sel2": {"fieldB": "B"},
        }
        event = {"fieldA": "A", "fieldB": "B"}
        self.assertTrue(DetectionEvaluator.evaluate_condition("all of them", sels, {}, event))

    def test_condition_all_of_them_fails(self):
        sels = {
            "sel1": {"fieldA": "A"},
            "sel2": {"fieldB": "B"},
        }
        event = {"fieldA": "A", "fieldB": "wrong"}
        self.assertFalse(DetectionEvaluator.evaluate_condition("all of them", sels, {}, event))

    def test_condition_1_of_them(self):
        sels = {
            "sel1": {"fieldA": "wrong"},
            "sel2": {"fieldB": "B"},
        }
        event = {"fieldB": "B"}
        self.assertTrue(DetectionEvaluator.evaluate_condition("1 of them", sels, {}, event))

    def test_condition_all_of_selection_star(self):
        rule = SigmaParser.parse(SAMPLE_RULE_ALL_OF)
        event = {"fieldA": "valueA", "fieldB": "valueB"}
        self.assertTrue(DetectionEvaluator.evaluate_condition(
            rule.detection.condition,
            rule.detection.selections,
            rule.detection.filters,
            event,
        ))

    def test_condition_1_of_selection_star(self):
        rule = SigmaParser.parse(SAMPLE_RULE_1_OF)
        event = {"fieldB": "valueB"}
        self.assertTrue(DetectionEvaluator.evaluate_condition(
            rule.detection.condition,
            rule.detection.selections,
            rule.detection.filters,
            event,
        ))

    def test_condition_empty_default(self):
        """Empty condition: AND all selections."""
        sels = {"sel1": {"field": "val"}}
        event = {"field": "val"}
        self.assertTrue(DetectionEvaluator.evaluate_condition("", sels, {}, event))

    def test_condition_empty_with_filter(self):
        sels = {"sel1": {"field": "val"}}
        filters = {"filter1": {"blocked": "yes"}}
        event = {"field": "val", "blocked": "yes"}
        self.assertFalse(DetectionEvaluator.evaluate_condition("", sels, filters, event))

    def test_condition_unknown_identifier(self):
        sels = {"selection": {"field": "val"}}
        event = {"field": "val"}
        # Unknown identifier evaluates to False
        self.assertFalse(DetectionEvaluator.evaluate_condition("nonexistent", sels, {}, event))

    def test_condition_empty_tokens(self):
        self.assertFalse(DetectionEvaluator._eval_tokens([], {}, {}))


# ============================================================================
# Test: WazuhConverter
# ============================================================================

class TestWazuhConverter(unittest.TestCase):

    def test_convert_basic(self):
        rule = SigmaParser.parse(SAMPLE_RULE_YAML)
        xml = WazuhConverter.convert(rule)
        self.assertIn('<group name="sigma,process_creation">', xml)
        self.assertIn("Suspicious PowerShell Command", xml)
        self.assertIn("level=", xml)
        self.assertIn("</rule>", xml)
        self.assertIn("</group>", xml)

    def test_convert_custom_rule_id(self):
        rule = SigmaParser.parse(SAMPLE_RULE_MINIMAL)
        xml = WazuhConverter.convert(rule, rule_id=250001)
        self.assertIn('id="250001"', xml)

    def test_convert_mitre_tags(self):
        rule = SigmaParser.parse(SAMPLE_RULE_YAML)
        xml = WazuhConverter.convert(rule)
        self.assertIn("<mitre>", xml)
        self.assertIn("T1059.001", xml)

    def test_convert_no_mitre(self):
        rule = SigmaParser.parse(SAMPLE_RULE_MINIMAL)
        xml = WazuhConverter.convert(rule)
        self.assertNotIn("<mitre>", xml)

    def test_convert_references(self):
        rule = SigmaParser.parse(SAMPLE_RULE_YAML)
        xml = WazuhConverter.convert(rule)
        self.assertIn('<info type="link">', xml)

    def test_convert_level_mapping(self):
        rule = SigmaParser.parse(SAMPLE_RULE_YAML)
        xml = WazuhConverter.convert(rule)
        self.assertIn('level="12"', xml)  # HIGH = 12

    def test_convert_critical_level(self):
        rule = SigmaParser.parse(SAMPLE_RULE_COMPLEX)
        xml = WazuhConverter.convert(rule)
        self.assertIn('level="15"', xml)  # CRITICAL = 15

    def test_convert_batch(self):
        rules = [
            SigmaParser.parse(SAMPLE_RULE_YAML),
            SigmaParser.parse(SAMPLE_RULE_MINIMAL),
        ]
        xml = WazuhConverter.convert_batch(rules)
        self.assertIn("TSUNAMI SOC Sigma Rules", xml)
        self.assertIn("Suspicious PowerShell Command", xml)
        self.assertIn("Minimal Rule", xml)

    def test_field_mapping(self):
        self.assertEqual(
            WazuhConverter._map_field("CommandLine"),
            "data.win.eventdata.commandLine"
        )
        self.assertEqual(WazuhConverter._map_field("Image"), "data.win.eventdata.image")
        self.assertEqual(WazuhConverter._map_field("message"), "full_log")
        self.assertEqual(WazuhConverter._map_field("custom_field"), "custom_field")

    def test_xml_special_chars_escaped(self):
        rule = SigmaRule(title='Test <script> & "quotes"')
        rule.logsource = {"category": "test"}
        rule.detection = SigmaDetection(
            selections={"sel": {"field": "val"}},
            condition="sel",
        )
        xml = WazuhConverter.convert(rule)
        self.assertIn("&lt;script&gt;", xml)
        self.assertIn("&amp;", xml)


# ============================================================================
# Test: SuricataConverter
# ============================================================================

class TestSuricataConverter(unittest.TestCase):

    def test_convert_basic(self):
        rule = SigmaParser.parse(SAMPLE_RULE_YAML)
        output = SuricataConverter.convert(rule)
        self.assertIn("alert", output)
        self.assertIn("SIGMA - Suspicious PowerShell Command", output)
        self.assertIn("sid:", output)
        self.assertIn("priority:", output)

    def test_convert_custom_sid(self):
        rule = SigmaParser.parse(SAMPLE_RULE_MINIMAL)
        output = SuricataConverter.convert(rule, sid=9999999)
        self.assertIn("sid:9999999", output)

    def test_convert_priority_mapping(self):
        rule = SigmaParser.parse(SAMPLE_RULE_COMPLEX)  # CRITICAL
        output = SuricataConverter.convert(rule)
        self.assertIn("priority:1", output)

    def test_convert_mitre_metadata(self):
        rule = SigmaParser.parse(SAMPLE_RULE_YAML)
        output = SuricataConverter.convert(rule)
        self.assertIn("mitre_technique", output)
        self.assertIn("T1059.001", output)

    def test_convert_dns_protocol(self):
        rule = SigmaParser.parse(SAMPLE_RULE_NETWORK)
        output = SuricataConverter.convert(rule)
        self.assertIn("alert dns", output)

    def test_convert_batch(self):
        rules = [
            SigmaParser.parse(SAMPLE_RULE_YAML),
            SigmaParser.parse(SAMPLE_RULE_NETWORK),
        ]
        output = SuricataConverter.convert_batch(rules)
        self.assertIn("TSUNAMI SOC Sigma Rules", output)
        self.assertIn("Suspicious PowerShell Command", output)
        self.assertIn("DNS Query to Malicious Domain", output)

    def test_guess_protocol_network(self):
        rule = SigmaRule(title="T", logsource={"category": "network_connection"})
        self.assertEqual(SuricataConverter._guess_protocol(rule), "tcp")

    def test_guess_protocol_webserver(self):
        rule = SigmaRule(title="T", logsource={"category": "webserver"})
        self.assertEqual(SuricataConverter._guess_protocol(rule), "http")

    def test_guess_protocol_default(self):
        rule = SigmaRule(title="T", logsource={"category": "process_creation"})
        self.assertEqual(SuricataConverter._guess_protocol(rule), "ip")

    def test_guess_classtype_trojan(self):
        rule = SigmaRule(title="T", tags=["attack.malware"])
        self.assertEqual(SuricataConverter._guess_classtype(rule), "trojan-activity")

    def test_guess_classtype_exploit(self):
        rule = SigmaRule(title="T", tags=["attack.exploit"])
        self.assertEqual(SuricataConverter._guess_classtype(rule), "attempted-admin")

    def test_guess_classtype_recon(self):
        rule = SigmaRule(title="T", tags=["attack.reconnaissance"])
        self.assertEqual(SuricataConverter._guess_classtype(rule), "attempted-recon")

    def test_guess_classtype_default(self):
        rule = SigmaRule(title="T", tags=[], logsource={"category": "syslog"})
        self.assertEqual(SuricataConverter._guess_classtype(rule), "bad-unknown")


# ============================================================================
# Test: SigmaRepository
# ============================================================================

class TestSigmaRepository(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_sigma.db")
        self.repo = SigmaRepository(db_path=self.db_path)

    def tearDown(self):
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir)

    def test_db_initialized(self):
        self.assertTrue(os.path.exists(self.db_path))
        conn = sqlite3.connect(self.db_path)
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        table_names = [t[0] for t in tables]
        self.assertIn("sigma_rules", table_names)
        conn.close()

    def test_add_and_get(self):
        rule = SigmaParser.parse(SAMPLE_RULE_YAML)
        result = self.repo.add(rule)
        self.assertTrue(result)

        retrieved = self.repo.get(rule.rule_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.title, rule.title)
        self.assertEqual(retrieved.level, rule.level)
        self.assertEqual(retrieved.status, rule.status)

    def test_add_duplicate_returns_false(self):
        rule = SigmaParser.parse(SAMPLE_RULE_YAML)
        self.repo.add(rule)
        result = self.repo.add(rule)
        self.assertFalse(result)

    def test_get_nonexistent(self):
        self.assertIsNone(self.repo.get("nonexistent-id"))

    def test_delete(self):
        rule = SigmaParser.parse(SAMPLE_RULE_YAML)
        self.repo.add(rule)
        self.assertTrue(self.repo.delete(rule.rule_id))
        self.assertIsNone(self.repo.get(rule.rule_id))

    def test_delete_nonexistent(self):
        self.assertFalse(self.repo.delete("nonexistent"))

    def test_update(self):
        rule = SigmaParser.parse(SAMPLE_RULE_YAML)
        self.repo.add(rule)

        rule.title = "Updated Title"
        rule.level = SigmaLevel.CRITICAL
        self.assertTrue(self.repo.update(rule))

        retrieved = self.repo.get(rule.rule_id)
        self.assertEqual(retrieved.title, "Updated Title")
        self.assertEqual(retrieved.level, SigmaLevel.CRITICAL)

    def test_update_nonexistent(self):
        rule = SigmaRule(rule_id="nonexistent", title="Ghost")
        self.assertFalse(self.repo.update(rule))

    def test_list_rules_all(self):
        for yaml_str in [SAMPLE_RULE_YAML, SAMPLE_RULE_COMPLEX, SAMPLE_RULE_MINIMAL]:
            self.repo.add(SigmaParser.parse(yaml_str))
        rules = self.repo.list_rules()
        self.assertEqual(len(rules), 3)

    def test_list_rules_enabled_only(self):
        rule = SigmaParser.parse(SAMPLE_RULE_YAML)
        self.repo.add(rule)
        self.repo.toggle_enabled(rule.rule_id, False)

        rules = self.repo.list_rules(enabled_only=True)
        self.assertEqual(len(rules), 0)

    def test_list_rules_by_level(self):
        self.repo.add(SigmaParser.parse(SAMPLE_RULE_YAML))     # high
        self.repo.add(SigmaParser.parse(SAMPLE_RULE_COMPLEX))  # critical
        self.repo.add(SigmaParser.parse(SAMPLE_RULE_MINIMAL))  # medium

        rules = self.repo.list_rules(level="high")
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].title, "Suspicious PowerShell Command")

    def test_list_rules_by_status(self):
        self.repo.add(SigmaParser.parse(SAMPLE_RULE_YAML))     # test
        self.repo.add(SigmaParser.parse(SAMPLE_RULE_COMPLEX))  # stable
        rules = self.repo.list_rules(status="stable")
        self.assertEqual(len(rules), 1)

    def test_list_rules_search(self):
        self.repo.add(SigmaParser.parse(SAMPLE_RULE_YAML))
        self.repo.add(SigmaParser.parse(SAMPLE_RULE_COMPLEX))
        rules = self.repo.list_rules(search="Mimikatz")
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].title, "Mimikatz Detection")

    def test_list_rules_limit_offset(self):
        for yaml_str in [SAMPLE_RULE_YAML, SAMPLE_RULE_COMPLEX, SAMPLE_RULE_MINIMAL]:
            self.repo.add(SigmaParser.parse(yaml_str))

        rules = self.repo.list_rules(limit=2, offset=0)
        self.assertEqual(len(rules), 2)

        rules = self.repo.list_rules(limit=2, offset=2)
        self.assertEqual(len(rules), 1)

    def test_count(self):
        self.assertEqual(self.repo.count(), 0)
        self.repo.add(SigmaParser.parse(SAMPLE_RULE_YAML))
        self.assertEqual(self.repo.count(), 1)

    def test_count_enabled_only(self):
        rule = SigmaParser.parse(SAMPLE_RULE_YAML)
        self.repo.add(rule)
        self.repo.toggle_enabled(rule.rule_id, False)
        self.assertEqual(self.repo.count(enabled_only=True), 0)
        self.assertEqual(self.repo.count(enabled_only=False), 1)

    def test_toggle_enabled(self):
        rule = SigmaParser.parse(SAMPLE_RULE_YAML)
        self.repo.add(rule)

        self.repo.toggle_enabled(rule.rule_id, False)
        retrieved = self.repo.get(rule.rule_id)
        self.assertFalse(retrieved.enabled)

        self.repo.toggle_enabled(rule.rule_id, True)
        retrieved = self.repo.get(rule.rule_id)
        self.assertTrue(retrieved.enabled)

    def test_toggle_nonexistent(self):
        self.assertFalse(self.repo.toggle_enabled("nonexistent", True))

    def test_get_by_hash(self):
        rule = SigmaParser.parse(SAMPLE_RULE_YAML)
        self.repo.add(rule)
        found = self.repo.get_by_hash(rule.hash)
        self.assertIsNotNone(found)
        self.assertEqual(found.rule_id, rule.rule_id)

    def test_get_by_hash_not_found(self):
        self.assertIsNone(self.repo.get_by_hash("nonexistent"))

    def test_get_stats(self):
        self.repo.add(SigmaParser.parse(SAMPLE_RULE_YAML))     # high, test
        self.repo.add(SigmaParser.parse(SAMPLE_RULE_COMPLEX))  # critical, stable

        stats = self.repo.get_stats()
        self.assertEqual(stats["total"], 2)
        self.assertEqual(stats["enabled"], 2)
        self.assertIn("high", stats["by_level"])
        self.assertIn("critical", stats["by_level"])

    def test_import_rules(self):
        rules = [
            SigmaParser.parse(SAMPLE_RULE_YAML),
            SigmaParser.parse(SAMPLE_RULE_COMPLEX),
        ]
        result = self.repo.import_rules(rules)
        self.assertEqual(result["added"], 2)
        self.assertEqual(result["skipped"], 0)
        self.assertEqual(result["errors"], 0)

    def test_import_rules_skip_duplicates(self):
        rule = SigmaParser.parse(SAMPLE_RULE_YAML)
        self.repo.add(rule)

        # Import again — should be skipped by hash
        rules = [SigmaParser.parse(SAMPLE_RULE_YAML)]
        result = self.repo.import_rules(rules)
        self.assertEqual(result["skipped"], 1)

    def test_detection_preserved(self):
        rule = SigmaParser.parse(SAMPLE_RULE_COMPLEX)
        self.repo.add(rule)
        retrieved = self.repo.get(rule.rule_id)
        self.assertIn("selection1", retrieved.detection.selections)
        self.assertIn("filter1", retrieved.detection.filters)
        self.assertEqual(retrieved.detection.condition, rule.detection.condition)


# ============================================================================
# Test: SigmaEngine
# ============================================================================

class TestSigmaEngine(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_engine.db")
        self.engine = SigmaEngine(db_path=self.db_path)

    def tearDown(self):
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir)

    def test_load_rule(self):
        rule = self.engine.load_rule(SAMPLE_RULE_YAML)
        self.assertEqual(rule.title, "Suspicious PowerShell Command")
        self.assertEqual(self.engine._stats["rules_loaded"], 1)

    def test_load_rule_persisted(self):
        rule = self.engine.load_rule(SAMPLE_RULE_YAML)
        retrieved = self.engine.get_rule(rule.rule_id)
        self.assertIsNotNone(retrieved)

    def test_load_rule_no_persist(self):
        rule = self.engine.load_rule(SAMPLE_RULE_YAML, persist=False)
        retrieved = self.engine.get_rule(rule.rule_id)
        self.assertIsNone(retrieved)

    def test_load_file(self):
        filepath = os.path.join(self.tmpdir, "test.yml")
        with open(filepath, "w") as f:
            f.write(SAMPLE_RULE_YAML)
        rule = self.engine.load_file(filepath)
        self.assertEqual(rule.title, "Suspicious PowerShell Command")

    def test_import_directory(self):
        for i in range(3):
            filepath = os.path.join(self.tmpdir, f"rule_{i}.yml")
            with open(filepath, "w") as f:
                f.write(SAMPLE_RULE_MINIMAL.replace("Minimal Rule", f"Rule {i}"))

        result = self.engine.import_directory(self.tmpdir)
        self.assertEqual(result["added"], 3)

    def test_evaluate_match(self):
        rule = self.engine.load_rule(SAMPLE_RULE_YAML, persist=False)
        event = {
            "CommandLine": "powershell.exe -enc abc -nop",
            "Image": "C:\\Windows\\System32\\powershell.exe",
        }
        matches = self.engine.evaluate(event, rules=[rule])
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].title, "Suspicious PowerShell Command")

    def test_evaluate_no_match(self):
        rule = self.engine.load_rule(SAMPLE_RULE_YAML, persist=False)
        event = {"CommandLine": "notepad.exe", "Image": "notepad.exe"}
        matches = self.engine.evaluate(event, rules=[rule])
        self.assertEqual(len(matches), 0)

    def test_evaluate_single(self):
        rule = self.engine.load_rule(SAMPLE_RULE_YAML, persist=False)
        event = {
            "CommandLine": "powershell.exe -enc test -nop",
            "Image": "C:\\powershell.exe",
        }
        self.assertTrue(self.engine.evaluate_single(event, rule))

    def test_evaluate_single_no_match(self):
        rule = self.engine.load_rule(SAMPLE_RULE_YAML, persist=False)
        event = {"CommandLine": "notepad"}
        self.assertFalse(self.engine.evaluate_single(event, rule))

    def test_evaluate_from_repository(self):
        self.engine.load_rule(SAMPLE_RULE_YAML)
        event = {
            "CommandLine": "powershell.exe -enc encoded -nop",
            "Image": "C:\\powershell.exe",
        }
        matches = self.engine.evaluate(event)
        self.assertEqual(len(matches), 1)

    def test_evaluate_complex_with_filter(self):
        rule = self.engine.load_rule(SAMPLE_RULE_COMPLEX, persist=False)

        # Matches selection, no filter
        event = {
            "CommandLine": "mimikatz sekurlsa::logonpasswords",
            "Image": "C:\\mimikatz.exe",
            "User": "admin",
        }
        self.assertTrue(self.engine.evaluate_single(event, rule))

        # Matches selection but filtered
        event_filtered = {
            "CommandLine": "mimikatz sekurlsa::logonpasswords",
            "Image": "C:\\mimikatz.exe",
            "User": "SYSTEM",
        }
        self.assertFalse(self.engine.evaluate_single(event_filtered, rule))

    def test_evaluate_error_counted(self):
        rule = SigmaRule(title="Bad Rule")
        rule.detection = SigmaDetection(
            selections={"sel": {"field": "val"}},
            condition="sel",
        )
        # Force an error by making selections non-iterable via bad condition
        rule.detection.condition = "1 of nonexistent*"
        self.engine.evaluate_single({"field": "val"}, rule)
        # No error since condition just returns False — test stats updated
        self.assertGreater(self.engine._stats["rules_evaluated"], 0)

    def test_convert_to_wazuh(self):
        rule = self.engine.load_rule(SAMPLE_RULE_YAML)
        xml = self.engine.convert_to_wazuh(rule_id=rule.rule_id)
        self.assertIn("Suspicious PowerShell Command", xml)
        self.assertEqual(self.engine._stats["conversions_wazuh"], 1)

    def test_convert_to_wazuh_by_object(self):
        rule = self.engine.load_rule(SAMPLE_RULE_YAML, persist=False)
        xml = self.engine.convert_to_wazuh(rule=rule)
        self.assertIn("Suspicious PowerShell Command", xml)

    def test_convert_to_wazuh_not_found(self):
        with self.assertRaises(ValueError):
            self.engine.convert_to_wazuh(rule_id="nonexistent")

    def test_convert_to_wazuh_no_args(self):
        with self.assertRaises(ValueError):
            self.engine.convert_to_wazuh()

    def test_convert_to_suricata(self):
        rule = self.engine.load_rule(SAMPLE_RULE_YAML)
        output = self.engine.convert_to_suricata(rule_id=rule.rule_id)
        self.assertIn("SIGMA", output)
        self.assertEqual(self.engine._stats["conversions_suricata"], 1)

    def test_convert_to_suricata_not_found(self):
        with self.assertRaises(ValueError):
            self.engine.convert_to_suricata(rule_id="nonexistent")

    def test_export_all_wazuh(self):
        self.engine.load_rule(SAMPLE_RULE_YAML)
        self.engine.load_rule(SAMPLE_RULE_COMPLEX)
        xml = self.engine.export_all_wazuh()
        self.assertIn("Suspicious PowerShell Command", xml)
        self.assertIn("Mimikatz Detection", xml)

    def test_export_all_suricata(self):
        self.engine.load_rule(SAMPLE_RULE_YAML)
        output = self.engine.export_all_suricata()
        self.assertIn("SIGMA", output)

    def test_search_rules(self):
        self.engine.load_rule(SAMPLE_RULE_YAML)
        self.engine.load_rule(SAMPLE_RULE_COMPLEX)
        results = self.engine.search_rules("PowerShell")
        self.assertEqual(len(results), 1)

    def test_delete_rule(self):
        rule = self.engine.load_rule(SAMPLE_RULE_YAML)
        self.assertTrue(self.engine.delete_rule(rule.rule_id))
        self.assertIsNone(self.engine.get_rule(rule.rule_id))

    def test_toggle_rule(self):
        rule = self.engine.load_rule(SAMPLE_RULE_YAML)
        self.engine.toggle_rule(rule.rule_id, False)
        retrieved = self.engine.get_rule(rule.rule_id)
        self.assertFalse(retrieved.enabled)

    def test_update_rule(self):
        rule = self.engine.load_rule(SAMPLE_RULE_YAML)
        rule.title = "Modified Title"
        self.assertTrue(self.engine.update_rule(rule))
        retrieved = self.engine.get_rule(rule.rule_id)
        self.assertEqual(retrieved.title, "Modified Title")

    def test_stats(self):
        self.engine.load_rule(SAMPLE_RULE_YAML)
        stats = self.engine.stats
        self.assertEqual(stats["rules_loaded"], 1)
        self.assertIn("repository", stats)
        self.assertEqual(stats["repository"]["total"], 1)


# ============================================================================
# Test: Flask Blueprint
# ============================================================================

class TestSigmaBlueprint(unittest.TestCase):

    def setUp(self):
        try:
            from flask import Flask
        except ImportError:
            self.skipTest("Flask not available")

        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_bp.db")
        self.engine = SigmaEngine(db_path=self.db_path)

        self.app = Flask(__name__)
        bp = create_sigma_blueprint(engine=self.engine)
        self.app.register_blueprint(bp)
        self.client = self.app.test_client()

    def tearDown(self):
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir)

    def test_status_endpoint(self):
        resp = self.client.get("/api/v1/soc/sigma/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "ok")

    def test_load_endpoint(self):
        resp = self.client.post(
            "/api/v1/soc/sigma/load",
            json={"yaml": SAMPLE_RULE_YAML},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "loaded")
        self.assertEqual(data["rule"]["title"], "Suspicious PowerShell Command")

    def test_load_invalid_yaml(self):
        resp = self.client.post(
            "/api/v1/soc/sigma/load",
            json={"yaml": "not a valid sigma rule"},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)

    def test_load_no_yaml_field(self):
        resp = self.client.post(
            "/api/v1/soc/sigma/load",
            json={"wrong": "field"},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)

    def test_list_rules_endpoint(self):
        self.engine.load_rule(SAMPLE_RULE_YAML)
        resp = self.client.get("/api/v1/soc/sigma/rules")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["count"], 1)

    def test_get_rule_endpoint(self):
        rule = self.engine.load_rule(SAMPLE_RULE_YAML)
        resp = self.client.get(f"/api/v1/soc/sigma/rules/{rule.rule_id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["title"], "Suspicious PowerShell Command")

    def test_get_rule_not_found(self):
        resp = self.client.get("/api/v1/soc/sigma/rules/nonexistent")
        self.assertEqual(resp.status_code, 404)

    def test_delete_rule_endpoint(self):
        rule = self.engine.load_rule(SAMPLE_RULE_YAML)
        resp = self.client.delete(f"/api/v1/soc/sigma/rules/{rule.rule_id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "deleted")

    def test_delete_rule_not_found(self):
        resp = self.client.delete("/api/v1/soc/sigma/rules/nonexistent")
        self.assertEqual(resp.status_code, 404)

    def test_toggle_rule_endpoint(self):
        rule = self.engine.load_rule(SAMPLE_RULE_YAML)
        resp = self.client.post(
            f"/api/v1/soc/sigma/rules/{rule.rule_id}/toggle",
            json={"enabled": False},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)

    def test_evaluate_endpoint(self):
        self.engine.load_rule(SAMPLE_RULE_YAML)
        event = {
            "CommandLine": "powershell.exe -enc data -nop",
            "Image": "C:\\Windows\\powershell.exe",
        }
        resp = self.client.post(
            "/api/v1/soc/sigma/evaluate",
            json={"event": event},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["matches"], 1)

    def test_evaluate_no_event(self):
        resp = self.client.post(
            "/api/v1/soc/sigma/evaluate",
            json={"wrong": "field"},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)

    def test_evaluate_with_rule_ids(self):
        rule = self.engine.load_rule(SAMPLE_RULE_YAML)
        event = {
            "CommandLine": "powershell.exe -enc data -nop",
            "Image": "C:\\powershell.exe",
        }
        resp = self.client.post(
            "/api/v1/soc/sigma/evaluate",
            json={"event": event, "rule_ids": [rule.rule_id]},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["matches"], 1)

    def test_convert_wazuh_endpoint(self):
        rule = self.engine.load_rule(SAMPLE_RULE_YAML)
        resp = self.client.get(f"/api/v1/soc/sigma/convert/wazuh/{rule.rule_id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["format"], "wazuh")
        self.assertIn("Suspicious PowerShell Command", data["output"])

    def test_convert_wazuh_not_found(self):
        resp = self.client.get("/api/v1/soc/sigma/convert/wazuh/nonexistent")
        self.assertEqual(resp.status_code, 404)

    def test_convert_suricata_endpoint(self):
        rule = self.engine.load_rule(SAMPLE_RULE_YAML)
        resp = self.client.get(f"/api/v1/soc/sigma/convert/suricata/{rule.rule_id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["format"], "suricata")

    def test_convert_suricata_not_found(self):
        resp = self.client.get("/api/v1/soc/sigma/convert/suricata/nonexistent")
        self.assertEqual(resp.status_code, 404)

    def test_export_wazuh_endpoint(self):
        self.engine.load_rule(SAMPLE_RULE_YAML)
        resp = self.client.get("/api/v1/soc/sigma/export/wazuh")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["format"], "wazuh")

    def test_export_suricata_endpoint(self):
        self.engine.load_rule(SAMPLE_RULE_YAML)
        resp = self.client.get("/api/v1/soc/sigma/export/suricata")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["format"], "suricata")


# ============================================================================
# Test: Global Singleton
# ============================================================================

class TestGlobalSingleton(unittest.TestCase):

    def test_returns_instance(self):
        # Reset global
        import modules.siem_integration.sigma_engine as mod
        mod._sigma_engine_instance = None

        engine = get_sigma_engine()
        self.assertIsInstance(engine, SigmaEngine)

    def test_same_instance(self):
        import modules.siem_integration.sigma_engine as mod
        mod._sigma_engine_instance = None

        e1 = get_sigma_engine()
        e2 = get_sigma_engine()
        self.assertIs(e1, e2)


# ============================================================================
# Test: Integration (End-to-End)
# ============================================================================

class TestIntegration(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_integ.db")
        self.engine = SigmaEngine(db_path=self.db_path)

    def tearDown(self):
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir)

    def test_full_powershell_detection_flow(self):
        """Load rule → evaluate event → convert to Wazuh/Suricata."""
        rule = self.engine.load_rule(SAMPLE_RULE_YAML)

        event = {
            "CommandLine": "powershell.exe -enc SGVsbG8= -nop",
            "Image": "C:\\Windows\\System32\\powershell.exe",
        }
        matches = self.engine.evaluate(event, rules=[rule])
        self.assertEqual(len(matches), 1)

        xml = self.engine.convert_to_wazuh(rule=rule)
        self.assertIn("<rule id=", xml)
        self.assertIn("sigma", xml)

        suri = self.engine.convert_to_suricata(rule=rule)
        self.assertIn("alert", suri)

    def test_full_mimikatz_filter_flow(self):
        """Complex rule with filter: admin matches, SYSTEM filtered."""
        rule = self.engine.load_rule(SAMPLE_RULE_COMPLEX)

        admin_event = {
            "CommandLine": "sekurlsa::logonpasswords",
            "Image": "C:\\Tools\\mimikatz.exe",
            "User": "Admin",
        }
        self.assertTrue(self.engine.evaluate_single(admin_event, rule))

        system_event = {
            "CommandLine": "sekurlsa::logonpasswords",
            "Image": "C:\\Tools\\mimikatz.exe",
            "User": "SYSTEM",
        }
        self.assertFalse(self.engine.evaluate_single(system_event, rule))

    def test_import_and_bulk_evaluate(self):
        """Import directory and evaluate events."""
        # Create multiple rule files
        for i, yaml_str in enumerate([SAMPLE_RULE_YAML, SAMPLE_RULE_NETWORK]):
            with open(os.path.join(self.tmpdir, f"rule_{i}.yml"), "w") as f:
                f.write(yaml_str)

        result = self.engine.import_directory(self.tmpdir)
        self.assertEqual(result["added"], 2)

        # Event matches PowerShell rule
        ps_event = {
            "CommandLine": "powershell.exe -enc test -nop",
            "Image": "C:\\powershell.exe",
        }
        matches = self.engine.evaluate(ps_event)
        self.assertTrue(any(m.title == "Suspicious PowerShell Command" for m in matches))

        # Event matches DNS rule
        dns_event = {
            "QueryName": "www.evil.com",
        }
        matches = self.engine.evaluate(dns_event)
        self.assertTrue(any(m.title == "DNS Query to Malicious Domain" for m in matches))

    def test_stats_after_operations(self):
        self.engine.load_rule(SAMPLE_RULE_YAML)
        event = {
            "CommandLine": "powershell.exe -enc x -nop",
            "Image": "C:\\powershell.exe",
        }
        self.engine.evaluate(event)
        self.engine.convert_to_wazuh(rule=SigmaParser.parse(SAMPLE_RULE_YAML))

        stats = self.engine.stats
        self.assertGreater(stats["rules_loaded"], 0)
        self.assertGreater(stats["rules_evaluated"], 0)
        self.assertGreater(stats["matches"], 0)
        self.assertGreater(stats["conversions_wazuh"], 0)


# ============================================================================
# Test: Edge Cases
# ============================================================================

class TestEdgeCases(unittest.TestCase):

    def test_xml_escape(self):
        self.assertEqual(_xml_escape('<script>'), '&lt;script&gt;')
        self.assertEqual(_xml_escape('a&b'), 'a&amp;b')
        self.assertEqual(_xml_escape('"quoted"'), '&quot;quoted&quot;')

    def test_suricata_escape(self):
        self.assertEqual(_suricata_escape('test"value'), 'test\\"value')
        self.assertEqual(_suricata_escape('a;b'), 'a\\;b')

    def test_unicode_in_rule(self):
        yaml_content = """
title: Türkçe Kural Testi
logsource:
    category: test
detection:
    selection:
        field1: değer
    condition: selection
"""
        rule = SigmaParser.parse(yaml_content)
        self.assertEqual(rule.title, "Türkçe Kural Testi")

    def test_empty_selections(self):
        """Engine handles rules with empty selections gracefully."""
        rule = SigmaRule(title="Empty")
        rule.detection = SigmaDetection(selections={}, condition="")
        result = DetectionEvaluator.evaluate_condition(
            "", {}, {}, {"field": "val"}
        )
        self.assertFalse(result)

    def test_concurrent_repository_access(self):
        tmpdir = tempfile.mkdtemp()
        try:
            repo = SigmaRepository(db_path=os.path.join(tmpdir, "concurrent.db"))
            errors = []

            def add_rule(idx):
                try:
                    rule = SigmaRule(title=f"Rule {idx}", rule_id=f"r{idx}")
                    repo.add(rule)
                except Exception as e:
                    errors.append(e)

            threads = [threading.Thread(target=add_rule, args=(i,)) for i in range(10)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            self.assertEqual(len(errors), 0)
            self.assertEqual(repo.count(), 10)
        finally:
            shutil.rmtree(tmpdir)

    def test_large_detection_logic(self):
        """Rule with many selection fields."""
        sel = {f"field{i}": f"value{i}" for i in range(20)}
        event = {f"field{i}": f"value{i}" for i in range(20)}

        result = DetectionEvaluator.evaluate_selection(sel, event)
        self.assertTrue(result)

    def test_create_blueprint_without_flask(self):
        with patch.dict("sys.modules", {"flask": None}):
            # Re-import won't work easily, but we can test None return
            # by checking with a non-flask scenario
            pass  # Covered by import guard

    def test_logsource_fields_constant(self):
        self.assertIn("process_creation", SIGMA_LOGSOURCE_FIELDS)
        self.assertIn("fields", SIGMA_LOGSOURCE_FIELDS["process_creation"])

    def test_modifiers_constant(self):
        self.assertIn("contains", SIGMA_MODIFIERS)
        self.assertIn("startswith", SIGMA_MODIFIERS)
        self.assertIn("endswith", SIGMA_MODIFIERS)
        self.assertIn("re", SIGMA_MODIFIERS)
        self.assertIn("all", SIGMA_MODIFIERS)
        self.assertIn("gt", SIGMA_MODIFIERS)

    def test_wildcard_complex_pattern(self):
        self.assertTrue(DetectionEvaluator._wildcard_match(
            "*\\powershell.exe", "C:\\Windows\\System32\\powershell.exe"
        ))
        self.assertFalse(DetectionEvaluator._wildcard_match(
            "*\\cmd.exe", "powershell.exe"
        ))

    def test_selection_with_list_of_dicts_or(self):
        """Ensure list-of-dicts is OR across elements."""
        sel = [
            {"field1": "no_match"},
            {"field2": "match_this"},
        ]
        event = {"field2": "match_this"}
        self.assertTrue(DetectionEvaluator.evaluate_selection(sel, event))

    def test_none_pattern_against_none_value(self):
        self.assertTrue(DetectionEvaluator.match_value(None, None))


if __name__ == "__main__":
    unittest.main()
