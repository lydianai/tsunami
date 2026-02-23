#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI SOC - Sigma Rule Engine
    Detection Rule Management, Conversion & Runtime Evaluation
================================================================================

    Features:
    - Full Sigma v2 YAML rule parser with validation
    - Detection logic compiler (AND/OR/NOT boolean algebra)
    - Rule → Wazuh XML converter (ossec rules format)
    - Rule → Suricata rule converter (alert tcp/udp rules)
    - Python runtime evaluator (match log events against rules)
    - Rule repository management (CRUD) with SQLite persistence
    - SigmaHQ community rules import (from filesystem/archive)
    - Rule tagging, versioning, and metadata tracking
    - Severity/status mapping to TSUNAMI Alert Format
    - Thread-safe operations with connection pooling
    - Flask Blueprint for rule management API
    - Export rules in native/converted formats

================================================================================
"""

import copy
import hashlib
import json
import logging
import os
import re
import sqlite3
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger("soc.sigma")


# ============================================================================
# Constants & Enums
# ============================================================================

class SigmaStatus(Enum):
    """Sigma rule status levels."""
    STABLE = "stable"
    TEST = "test"
    EXPERIMENTAL = "experimental"
    DEPRECATED = "deprecated"
    UNSUPPORTED = "unsupported"

    @classmethod
    def from_string(cls, s: str) -> "SigmaStatus":
        if not s:
            return cls.EXPERIMENTAL
        s_lower = s.strip().lower()
        for member in cls:
            if member.value == s_lower:
                return member
        return cls.EXPERIMENTAL


class SigmaLevel(Enum):
    """Sigma severity levels mapped to numeric values."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

    @classmethod
    def from_string(cls, s: str) -> "SigmaLevel":
        if not s:
            return cls.MEDIUM
        s_lower = s.strip().lower()
        for member in cls:
            if member.value == s_lower:
                return member
        if s_lower == "info":
            return cls.INFORMATIONAL
        return cls.MEDIUM

    @property
    def numeric(self) -> int:
        return {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "informational": 1,
        }.get(self.value, 3)

    @property
    def wazuh_level(self) -> int:
        """Map to Wazuh alert level (0-16)."""
        return {
            "critical": 15,
            "high": 12,
            "medium": 8,
            "low": 5,
            "informational": 3,
        }.get(self.value, 8)


# Standard Sigma logsource categories and their typical field mappings
SIGMA_LOGSOURCE_FIELDS = {
    "process_creation": {
        "product": "windows",
        "fields": ["CommandLine", "Image", "ParentImage", "User",
                   "IntegrityLevel", "ParentCommandLine", "OriginalFileName"],
    },
    "network_connection": {
        "product": "windows",
        "fields": ["DestinationIp", "DestinationPort", "SourceIp",
                   "SourcePort", "Image", "User"],
    },
    "file_event": {
        "product": "windows",
        "fields": ["TargetFilename", "Image", "User"],
    },
    "registry_event": {
        "product": "windows",
        "fields": ["TargetObject", "Details", "Image"],
    },
    "dns_query": {
        "product": "windows",
        "fields": ["QueryName", "QueryResults", "Image"],
    },
    "firewall": {
        "product": "linux",
        "fields": ["src_ip", "dst_ip", "src_port", "dst_port", "action"],
    },
    "webserver": {
        "product": "linux",
        "fields": ["c-uri", "cs-method", "c-ip", "sc-status"],
    },
    "syslog": {
        "product": "linux",
        "fields": ["facility", "severity", "message", "hostname", "program"],
    },
    "antivirus": {
        "product": "any",
        "fields": ["Filename", "Signature", "Action"],
    },
}

# Sigma modifier operators
SIGMA_MODIFIERS = {
    "contains",
    "startswith",
    "endswith",
    "base64",
    "base64offset",
    "re",
    "cidr",
    "all",
    "gt",
    "gte",
    "lt",
    "lte",
    "windash",
    "wide",
    "utf16",
    "utf16le",
    "utf16be",
}


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class SigmaDetection:
    """Parsed detection logic from a Sigma rule."""
    selections: Dict[str, Any] = field(default_factory=dict)
    filters: Dict[str, Any] = field(default_factory=dict)
    condition: str = ""
    _compiled: Optional[Callable] = field(default=None, repr=False)


@dataclass
class SigmaRule:
    """Complete parsed Sigma rule."""
    rule_id: str = ""
    title: str = ""
    description: str = ""
    status: SigmaStatus = SigmaStatus.EXPERIMENTAL
    level: SigmaLevel = SigmaLevel.MEDIUM
    author: str = ""
    date: str = ""
    modified: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    logsource: Dict[str, str] = field(default_factory=dict)
    detection: SigmaDetection = field(default_factory=SigmaDetection)
    falsepositives: List[str] = field(default_factory=list)
    fields: List[str] = field(default_factory=list)
    raw_yaml: str = ""
    source_file: str = ""
    # Computed
    mitre_techniques: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    hash: str = ""
    imported_at: str = ""
    enabled: bool = True

    def __post_init__(self):
        if not self.rule_id:
            self.rule_id = str(uuid.uuid4())
        if not self.imported_at:
            self.imported_at = datetime.now(timezone.utc).isoformat()
        if not self.hash and self.raw_yaml:
            self.hash = hashlib.sha256(self.raw_yaml.encode()).hexdigest()[:32]
        self._extract_mitre()

    def _extract_mitre(self):
        """Extract MITRE ATT&CK info from tags."""
        for tag in self.tags:
            tag_lower = tag.lower().strip()
            if tag_lower.startswith("attack.t"):
                tech_id = tag_lower.replace("attack.", "").upper()
                if tech_id not in self.mitre_techniques:
                    self.mitre_techniques.append(tech_id)
            elif tag_lower.startswith("attack."):
                tactic = tag_lower.replace("attack.", "").replace("_", " ").title()
                if tactic not in self.mitre_tactics:
                    self.mitre_tactics.append(tactic)

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "status": self.status.value,
            "level": self.level.value,
            "author": self.author,
            "date": self.date,
            "modified": self.modified,
            "references": self.references,
            "tags": self.tags,
            "logsource": self.logsource,
            "detection_condition": self.detection.condition,
            "falsepositives": self.falsepositives,
            "fields": self.fields,
            "mitre_techniques": self.mitre_techniques,
            "mitre_tactics": self.mitre_tactics,
            "hash": self.hash,
            "imported_at": self.imported_at,
            "enabled": self.enabled,
            "source_file": self.source_file,
        }
        return d


# ============================================================================
# Sigma YAML Parser
# ============================================================================

class SigmaParseError(Exception):
    """Raised when a Sigma rule cannot be parsed."""
    pass


class SigmaParser:
    """Parse Sigma YAML rules into SigmaRule objects."""

    @staticmethod
    def parse(yaml_content: str, source_file: str = "") -> SigmaRule:
        """Parse a single Sigma YAML rule string into a SigmaRule object."""
        try:
            import yaml
        except ImportError:
            raise SigmaParseError("PyYAML is required for Sigma rule parsing")

        if not yaml_content or not yaml_content.strip():
            raise SigmaParseError("Empty YAML content")

        try:
            data = yaml.safe_load(yaml_content)
        except Exception as e:
            raise SigmaParseError(f"Invalid YAML: {e}")

        if not isinstance(data, dict):
            raise SigmaParseError("YAML root must be a mapping")

        if "title" not in data:
            raise SigmaParseError("Missing required field: title")
        if "detection" not in data:
            raise SigmaParseError("Missing required field: detection")
        if "logsource" not in data:
            raise SigmaParseError("Missing required field: logsource")

        detection_raw = data.get("detection", {})
        if not isinstance(detection_raw, dict):
            raise SigmaParseError("detection must be a mapping")

        condition = detection_raw.pop("condition", "")
        if isinstance(condition, list):
            condition = " or ".join(str(c) for c in condition)
        condition = str(condition).strip()

        selections = {}
        filters = {}
        for key, value in detection_raw.items():
            if key.startswith("filter"):
                filters[key] = value
            else:
                selections[key] = value

        detection = SigmaDetection(
            selections=selections,
            filters=filters,
            condition=condition,
        )

        logsource = data.get("logsource", {})
        if not isinstance(logsource, dict):
            logsource = {}

        tags = data.get("tags", [])
        if not isinstance(tags, list):
            tags = [str(tags)] if tags else []

        refs = data.get("references", [])
        if not isinstance(refs, list):
            refs = [str(refs)] if refs else []

        fps = data.get("falsepositives", [])
        if not isinstance(fps, list):
            fps = [str(fps)] if fps else []

        rule_fields = data.get("fields", [])
        if not isinstance(rule_fields, list):
            rule_fields = []

        rule = SigmaRule(
            rule_id=str(data.get("id", uuid.uuid4())),
            title=str(data.get("title", "")),
            description=str(data.get("description", "")),
            status=SigmaStatus.from_string(str(data.get("status", ""))),
            level=SigmaLevel.from_string(str(data.get("level", ""))),
            author=str(data.get("author", "")),
            date=str(data.get("date", "")),
            modified=str(data.get("modified", "")),
            references=refs,
            tags=[str(t) for t in tags],
            logsource=logsource,
            detection=detection,
            falsepositives=[str(f) for f in fps],
            fields=[str(f) for f in rule_fields],
            raw_yaml=yaml_content,
            source_file=source_file,
        )

        return rule

    @staticmethod
    def parse_file(filepath: str) -> SigmaRule:
        """Parse a Sigma rule from a file path."""
        path = Path(filepath)
        if not path.exists():
            raise SigmaParseError(f"File not found: {filepath}")
        if not path.suffix.lower() in (".yml", ".yaml"):
            raise SigmaParseError(f"Not a YAML file: {filepath}")

        content = path.read_text(encoding="utf-8")
        return SigmaParser.parse(content, source_file=str(path))

    @staticmethod
    def parse_directory(dirpath: str, recursive: bool = True) -> List[SigmaRule]:
        """Parse all Sigma rules from a directory."""
        rules = []
        path = Path(dirpath)
        if not path.exists() or not path.is_dir():
            return rules

        pattern = "**/*.yml" if recursive else "*.yml"
        for yml_file in path.glob(pattern):
            try:
                rule = SigmaParser.parse_file(str(yml_file))
                rules.append(rule)
            except SigmaParseError as e:
                logger.warning(f"Skipping {yml_file}: {e}")
            except Exception as e:
                logger.error(f"Error parsing {yml_file}: {e}")

        # Also scan .yaml
        yaml_pattern = "**/*.yaml" if recursive else "*.yaml"
        for yml_file in path.glob(yaml_pattern):
            try:
                rule = SigmaParser.parse_file(str(yml_file))
                rules.append(rule)
            except SigmaParseError as e:
                logger.warning(f"Skipping {yml_file}: {e}")
            except Exception as e:
                logger.error(f"Error parsing {yml_file}: {e}")

        return rules


# ============================================================================
# Detection Logic Compiler & Evaluator
# ============================================================================

class DetectionEvaluator:
    """
    Evaluate Sigma detection logic against log events.
    Supports the full Sigma condition language:
    - selection references
    - AND, OR, NOT operators
    - 1/all of selection* patterns
    - Parenthetical grouping
    - Field modifiers: contains, startswith, endswith, re, all, gt/gte/lt/lte
    """

    @staticmethod
    def match_value(pattern: Any, value: Any, modifiers: List[str] = None) -> bool:
        """Match a single pattern against a single value with modifiers."""
        if modifiers is None:
            modifiers = []

        if value is None:
            return pattern is None

        str_value = str(value)
        str_pattern = str(pattern)

        if "re" in modifiers:
            try:
                return bool(re.search(str_pattern, str_value, re.IGNORECASE))
            except re.error:
                return False

        if "contains" in modifiers:
            return str_pattern.lower() in str_value.lower()
        if "startswith" in modifiers:
            return str_value.lower().startswith(str_pattern.lower())
        if "endswith" in modifiers:
            return str_value.lower().endswith(str_pattern.lower())

        # Numeric comparisons
        if "gt" in modifiers:
            try:
                return float(value) > float(pattern)
            except (ValueError, TypeError):
                return False
        if "gte" in modifiers:
            try:
                return float(value) >= float(pattern)
            except (ValueError, TypeError):
                return False
        if "lt" in modifiers:
            try:
                return float(value) < float(pattern)
            except (ValueError, TypeError):
                return False
        if "lte" in modifiers:
            try:
                return float(value) <= float(pattern)
            except (ValueError, TypeError):
                return False

        # Sigma default: case-insensitive wildcard matching
        return DetectionEvaluator._wildcard_match(str_pattern, str_value)

    @staticmethod
    def _wildcard_match(pattern: str, value: str) -> bool:
        """Sigma-style case-insensitive wildcard matching. * and ? supported."""
        # Convert Sigma wildcard to regex
        regex_parts = []
        i = 0
        while i < len(pattern):
            c = pattern[i]
            if c == '*':
                regex_parts.append('.*')
            elif c == '?':
                regex_parts.append('.')
            elif c == '\\' and i + 1 < len(pattern) and pattern[i + 1] in ('*', '?', '\\'):
                regex_parts.append(re.escape(pattern[i + 1]))
                i += 1
            else:
                regex_parts.append(re.escape(c))
            i += 1

        regex = '^' + ''.join(regex_parts) + '$'
        try:
            return bool(re.match(regex, value, re.IGNORECASE | re.DOTALL))
        except re.error:
            return pattern.lower() == value.lower()

    @staticmethod
    def _parse_field_modifiers(field_name: str) -> Tuple[str, List[str]]:
        """Parse field|modifier1|modifier2 syntax."""
        parts = field_name.split("|")
        base_field = parts[0]
        modifiers = [m for m in parts[1:] if m in SIGMA_MODIFIERS]
        return base_field, modifiers

    @staticmethod
    def evaluate_selection(selection: Any, event: Dict[str, Any]) -> bool:
        """
        Evaluate a single selection block against an event.

        Selection can be:
        - Dict of field: value/list-of-values (OR within field, AND across fields)
        - List of dicts (OR across list elements)
        """
        if isinstance(selection, list):
            # List of conditions: OR
            return any(
                DetectionEvaluator.evaluate_selection(item, event)
                for item in selection
            )

        if not isinstance(selection, dict):
            return False

        # Dict: each key-value pair is AND-ed
        for raw_field, pattern in selection.items():
            base_field, modifiers = DetectionEvaluator._parse_field_modifiers(raw_field)

            event_value = event.get(base_field)

            # Handle case-insensitive field lookup
            if event_value is None:
                for k, v in event.items():
                    if k.lower() == base_field.lower():
                        event_value = v
                        break

            if isinstance(pattern, list):
                if "all" in modifiers:
                    # All patterns must match
                    if not all(
                        DetectionEvaluator.match_value(p, event_value, modifiers)
                        for p in pattern
                    ):
                        return False
                else:
                    # Any pattern can match (OR)
                    if not any(
                        DetectionEvaluator.match_value(p, event_value, modifiers)
                        for p in pattern
                    ):
                        return False
            else:
                if not DetectionEvaluator.match_value(pattern, event_value, modifiers):
                    return False

        return True

    @staticmethod
    def evaluate_condition(condition: str, selections: Dict[str, Any],
                          filters: Dict[str, Any], event: Dict[str, Any]) -> bool:
        """
        Evaluate the Sigma condition string.

        Supports:
        - Simple: 'selection'
        - Boolean: 'selection1 and selection2', 'selection1 or selection2'
        - Negation: 'selection and not filter'
        - Patterns: '1 of selection*', 'all of selection*'
        - Grouping: '(selection1 or selection2) and not filter'
        - 'all of them', '1 of them'
        """
        if not condition:
            # Default: AND all selections, AND NOT all filters
            sel_match = all(
                DetectionEvaluator.evaluate_selection(v, event)
                for v in selections.values()
            ) if selections else False

            if filters:
                filter_match = any(
                    DetectionEvaluator.evaluate_selection(v, event)
                    for v in filters.values()
                )
                return sel_match and not filter_match
            return sel_match

        # Tokenize the condition
        tokens = DetectionEvaluator._tokenize_condition(condition)

        # Build combined namespace
        all_names = {}
        all_names.update(selections)
        all_names.update(filters)

        return DetectionEvaluator._eval_tokens(tokens, all_names, event)

    @staticmethod
    def _tokenize_condition(condition: str) -> List[str]:
        """Tokenize a Sigma condition string."""
        # Handle special patterns: "1 of ...", "all of ..."
        tokens = []
        # Split preserving parentheses and operators
        parts = re.findall(
            r'\(|\)|and|or|not|all\s+of\s+[^\s()]+|all\s+of\s+them|'
            r'1\s+of\s+[^\s()]+|1\s+of\s+them|[^\s()]+',
            condition,
            re.IGNORECASE
        )
        return [p.strip() for p in parts if p.strip()]

    @staticmethod
    def _eval_tokens(tokens: List[str], names: Dict[str, Any],
                     event: Dict[str, Any]) -> bool:
        """Evaluate tokenized condition recursively."""
        if not tokens:
            return False

        result, _ = DetectionEvaluator._parse_or(tokens, 0, names, event)
        return result

    @staticmethod
    def _parse_or(tokens: List[str], pos: int, names: Dict, event: Dict) -> Tuple[bool, int]:
        """Parse OR expressions (lowest precedence)."""
        left, pos = DetectionEvaluator._parse_and(tokens, pos, names, event)

        while pos < len(tokens) and tokens[pos].lower() == "or":
            pos += 1  # skip 'or'
            right, pos = DetectionEvaluator._parse_and(tokens, pos, names, event)
            left = left or right

        return left, pos

    @staticmethod
    def _parse_and(tokens: List[str], pos: int, names: Dict, event: Dict) -> Tuple[bool, int]:
        """Parse AND expressions."""
        left, pos = DetectionEvaluator._parse_not(tokens, pos, names, event)

        while pos < len(tokens) and tokens[pos].lower() == "and":
            pos += 1  # skip 'and'
            right, pos = DetectionEvaluator._parse_not(tokens, pos, names, event)
            left = left and right

        return left, pos

    @staticmethod
    def _parse_not(tokens: List[str], pos: int, names: Dict, event: Dict) -> Tuple[bool, int]:
        """Parse NOT expressions."""
        if pos < len(tokens) and tokens[pos].lower() == "not":
            pos += 1
            val, pos = DetectionEvaluator._parse_atom(tokens, pos, names, event)
            return not val, pos
        return DetectionEvaluator._parse_atom(tokens, pos, names, event)

    @staticmethod
    def _parse_atom(tokens: List[str], pos: int, names: Dict, event: Dict) -> Tuple[bool, int]:
        """Parse atomic expressions (identifiers, parens, 'X of')."""
        if pos >= len(tokens):
            return False, pos

        token = tokens[pos]

        # Parenthetical grouping
        if token == "(":
            pos += 1
            result, pos = DetectionEvaluator._parse_or(tokens, pos, names, event)
            if pos < len(tokens) and tokens[pos] == ")":
                pos += 1
            return result, pos

        # "all of them" / "1 of them"
        token_lower = token.lower()
        if re.match(r'^(all|1)\s+of\s+them$', token_lower):
            quantifier = token_lower.split()[0]
            if quantifier == "all":
                result = all(
                    DetectionEvaluator.evaluate_selection(v, event)
                    for v in names.values()
                )
            else:
                result = any(
                    DetectionEvaluator.evaluate_selection(v, event)
                    for v in names.values()
                )
            return result, pos + 1

        # "all of selection*" / "1 of selection*"
        match = re.match(r'^(all|1)\s+of\s+(\S+)$', token_lower)
        if match:
            quantifier = match.group(1)
            pattern = match.group(2)

            if pattern.endswith("*"):
                prefix = pattern[:-1]
                matching = {
                    k: v for k, v in names.items()
                    if k.lower().startswith(prefix)
                }
            else:
                matching = {pattern: names.get(pattern, {})}

            if not matching:
                return False, pos + 1

            if quantifier == "all":
                result = all(
                    DetectionEvaluator.evaluate_selection(v, event)
                    for v in matching.values()
                )
            else:
                result = any(
                    DetectionEvaluator.evaluate_selection(v, event)
                    for v in matching.values()
                )
            return result, pos + 1

        # Simple selection identifier
        if token in names:
            result = DetectionEvaluator.evaluate_selection(names[token], event)
            return result, pos + 1

        # Unknown token — try as identifier anyway
        return False, pos + 1


# ============================================================================
# Wazuh Rule Converter
# ============================================================================

class WazuhConverter:
    """Convert Sigma rules to Wazuh XML rule format."""

    WAZUH_RULE_ID_START = 200000

    @staticmethod
    def convert(rule: SigmaRule, rule_id: int = 0) -> str:
        """Convert a Sigma rule to Wazuh XML rule format."""
        if rule_id == 0:
            # Generate from hash
            rule_id = WazuhConverter.WAZUH_RULE_ID_START + (
                int(hashlib.md5(rule.rule_id.encode()).hexdigest()[:6], 16) % 99999
            )

        level = rule.level.wazuh_level
        description = _xml_escape(rule.title)
        info = _xml_escape(rule.description) if rule.description else ""

        # Build match conditions from detection selections
        conditions = []
        for sel_name, sel_data in rule.detection.selections.items():
            if isinstance(sel_data, dict):
                for field_raw, value in sel_data.items():
                    base_field, modifiers = DetectionEvaluator._parse_field_modifiers(field_raw)
                    wazuh_field = WazuhConverter._map_field(base_field)
                    patterns = value if isinstance(value, list) else [value]
                    for p in patterns:
                        conditions.append((wazuh_field, str(p), modifiers))
            elif isinstance(sel_data, list):
                for item in sel_data:
                    if isinstance(item, dict):
                        for field_raw, value in item.items():
                            base_field, modifiers = DetectionEvaluator._parse_field_modifiers(field_raw)
                            wazuh_field = WazuhConverter._map_field(base_field)
                            patterns = value if isinstance(value, list) else [value]
                            for p in patterns:
                                conditions.append((wazuh_field, str(p), modifiers))

        lines = []
        lines.append(f'<group name="sigma,{_xml_escape(rule.logsource.get("category", "generic"))}">')
        lines.append(f'  <rule id="{rule_id}" level="{level}">')

        if info:
            lines.append(f'    <description>{description} - {info}</description>')
        else:
            lines.append(f'    <description>{description}</description>')

        # Conditions
        for wfield, pattern, mods in conditions:
            pattern_escaped = _xml_escape(pattern)
            if "re" in mods:
                if wfield == "full_log":
                    lines.append(f'    <regex>{pattern_escaped}</regex>')
                else:
                    lines.append(f'    <field name="{wfield}">{pattern_escaped}</field>')
            elif "contains" in mods:
                if wfield == "full_log":
                    lines.append(f'    <match>{pattern_escaped}</match>')
                else:
                    lines.append(f'    <field name="{wfield}">{pattern_escaped}</field>')
            else:
                if wfield == "full_log":
                    lines.append(f'    <match>{pattern_escaped}</match>')
                else:
                    lines.append(f'    <field name="{wfield}">{pattern_escaped}</field>')

        # MITRE
        if rule.mitre_techniques:
            lines.append('    <mitre>')
            for tech in rule.mitre_techniques:
                lines.append(f'      <id>{_xml_escape(tech)}</id>')
            lines.append('    </mitre>')

        # Group/tags
        group_parts = ["sigma"]
        if rule.logsource.get("category"):
            group_parts.append(rule.logsource["category"])
        if rule.logsource.get("product"):
            group_parts.append(rule.logsource["product"])
        lines.append(f'    <group>{",".join(_xml_escape(g) for g in group_parts)}</group>')

        # References
        for ref in rule.references[:3]:
            lines.append(f'    <info type="link">{_xml_escape(ref)}</info>')

        lines.append('  </rule>')
        lines.append('</group>')

        return '\n'.join(lines)

    @staticmethod
    def _map_field(sigma_field: str) -> str:
        """Map Sigma field names to Wazuh field names."""
        mapping = {
            "CommandLine": "data.win.eventdata.commandLine",
            "Image": "data.win.eventdata.image",
            "ParentImage": "data.win.eventdata.parentImage",
            "User": "data.win.eventdata.user",
            "TargetFilename": "data.win.eventdata.targetFilename",
            "TargetObject": "data.win.eventdata.targetObject",
            "Details": "data.win.eventdata.details",
            "DestinationIp": "data.win.eventdata.destinationIp",
            "DestinationPort": "data.win.eventdata.destinationPort",
            "SourceIp": "data.win.eventdata.sourceIp",
            "SourcePort": "data.win.eventdata.sourcePort",
            "QueryName": "data.win.eventdata.queryName",
            "OriginalFileName": "data.win.eventdata.originalFileName",
            "IntegrityLevel": "data.win.eventdata.integrityLevel",
            "ParentCommandLine": "data.win.eventdata.parentCommandLine",
            "Hashes": "data.win.eventdata.hashes",
            "LogonType": "data.win.eventdata.logonType",
            "EventID": "data.win.system.eventID",
            "message": "full_log",
        }
        return mapping.get(sigma_field, sigma_field.lower())

    @staticmethod
    def convert_batch(rules: List[SigmaRule]) -> str:
        """Convert multiple rules to a Wazuh rules XML file."""
        parts = ['<!-- TSUNAMI SOC Sigma Rules - Auto-generated -->\n']
        for i, rule in enumerate(rules):
            rid = WazuhConverter.WAZUH_RULE_ID_START + i
            parts.append(WazuhConverter.convert(rule, rule_id=rid))
            parts.append('')
        return '\n'.join(parts)


# ============================================================================
# Suricata Rule Converter
# ============================================================================

class SuricataConverter:
    """Convert Sigma rules to Suricata rule format."""

    SURICATA_SID_START = 9000000

    @staticmethod
    def convert(rule: SigmaRule, sid: int = 0) -> str:
        """Convert a Sigma rule to a Suricata rule string."""
        if sid == 0:
            sid = SuricataConverter.SURICATA_SID_START + (
                int(hashlib.md5(rule.rule_id.encode()).hexdigest()[:6], 16) % 999999
            )

        # Determine action and protocol
        action = "alert"
        protocol = SuricataConverter._guess_protocol(rule)

        # Determine network direction
        src_net = "$HOME_NET"
        dst_net = "$EXTERNAL_NET"
        src_port = "any"
        dst_port = "any"

        category = rule.logsource.get("category", "")
        if category in ("network_connection", "firewall"):
            dst_net = "any"

        # Build content matches
        contents = []
        for sel_name, sel_data in rule.detection.selections.items():
            if isinstance(sel_data, dict):
                for field_raw, value in sel_data.items():
                    _, modifiers = DetectionEvaluator._parse_field_modifiers(field_raw)
                    patterns = value if isinstance(value, list) else [value]
                    for p in patterns:
                        p_str = str(p).replace('*', '').replace('?', '')
                        if p_str:
                            content = f'content:"{_suricata_escape(p_str)}"'
                            if "contains" not in modifiers and "startswith" not in modifiers:
                                pass  # default exact
                            contents.append(content)
            elif isinstance(sel_data, list):
                for item in sel_data:
                    if isinstance(item, dict):
                        for field_raw, value in item.items():
                            _, modifiers = DetectionEvaluator._parse_field_modifiers(field_raw)
                            patterns = value if isinstance(value, list) else [value]
                            for p in patterns:
                                p_str = str(p).replace('*', '').replace('?', '')
                                if p_str:
                                    contents.append(f'content:"{_suricata_escape(p_str)}"')

        # Build metadata
        priority = SuricataConverter._level_to_priority(rule.level)
        msg = _suricata_escape(rule.title)

        opts = [f'msg:"SIGMA - {msg}"']
        opts.extend(contents[:10])  # Limit to 10 content matches
        opts.append(f'sid:{sid}')
        opts.append('rev:1')
        opts.append(f'priority:{priority}')

        if rule.mitre_techniques:
            mitre_str = ",".join(rule.mitre_techniques[:5])
            opts.append(f'metadata:mitre_technique {mitre_str}')

        classtype = SuricataConverter._guess_classtype(rule)
        if classtype:
            opts.append(f'classtype:{classtype}')

        opts_str = "; ".join(opts) + ";"

        return (
            f'{action} {protocol} {src_net} {src_port} -> '
            f'{dst_net} {dst_port} ({opts_str})'
        )

    @staticmethod
    def _guess_protocol(rule: SigmaRule) -> str:
        """Guess network protocol from logsource."""
        cat = rule.logsource.get("category", "").lower()
        if cat in ("dns_query", "dns"):
            return "dns"
        if cat in ("network_connection", "firewall"):
            return "tcp"
        if cat == "webserver":
            return "http"
        return "ip"

    @staticmethod
    def _level_to_priority(level: SigmaLevel) -> int:
        return {
            "critical": 1,
            "high": 2,
            "medium": 3,
            "low": 4,
            "informational": 5,
        }.get(level.value, 3)

    @staticmethod
    def _guess_classtype(rule: SigmaRule) -> str:
        """Guess Suricata classtype from rule context."""
        cat = rule.logsource.get("category", "").lower()
        tags = " ".join(rule.tags).lower()

        if "trojan" in tags or "malware" in tags:
            return "trojan-activity"
        if "exploit" in tags:
            return "attempted-admin"
        if cat == "dns_query":
            return "bad-unknown"
        if "reconnaissance" in tags or "discovery" in tags:
            return "attempted-recon"
        if cat in ("process_creation", "file_event", "registry_event"):
            return "policy-violation"
        return "bad-unknown"

    @staticmethod
    def convert_batch(rules: List[SigmaRule]) -> str:
        """Convert multiple rules to Suricata rules file format."""
        lines = ['# TSUNAMI SOC Sigma Rules - Auto-generated']
        for i, rule in enumerate(rules):
            sid = SuricataConverter.SURICATA_SID_START + i
            lines.append(SuricataConverter.convert(rule, sid=sid))
        return '\n'.join(lines)


# ============================================================================
# Rule Repository (SQLite)
# ============================================================================

class SigmaRepository:
    """SQLite-backed Sigma rule repository with CRUD operations."""

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            dalga_dir = Path.home() / ".dalga"
            dalga_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(dalga_dir / "sigma_rules.db")

        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS sigma_rules (
                    rule_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    status TEXT DEFAULT 'experimental',
                    level TEXT DEFAULT 'medium',
                    author TEXT DEFAULT '',
                    date TEXT DEFAULT '',
                    modified TEXT DEFAULT '',
                    references_json TEXT DEFAULT '[]',
                    tags_json TEXT DEFAULT '[]',
                    logsource_json TEXT DEFAULT '{}',
                    detection_json TEXT DEFAULT '{}',
                    falsepositives_json TEXT DEFAULT '[]',
                    fields_json TEXT DEFAULT '[]',
                    raw_yaml TEXT DEFAULT '',
                    source_file TEXT DEFAULT '',
                    mitre_techniques_json TEXT DEFAULT '[]',
                    mitre_tactics_json TEXT DEFAULT '[]',
                    hash TEXT DEFAULT '',
                    imported_at TEXT DEFAULT '',
                    enabled INTEGER DEFAULT 1,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_sigma_rules_title
                    ON sigma_rules(title);
                CREATE INDEX IF NOT EXISTS idx_sigma_rules_level
                    ON sigma_rules(level);
                CREATE INDEX IF NOT EXISTS idx_sigma_rules_status
                    ON sigma_rules(status);
                CREATE INDEX IF NOT EXISTS idx_sigma_rules_enabled
                    ON sigma_rules(enabled);
                CREATE INDEX IF NOT EXISTS idx_sigma_rules_hash
                    ON sigma_rules(hash);
            """)
            conn.commit()
            conn.close()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def add(self, rule: SigmaRule) -> bool:
        """Add a rule to the repository. Returns True if added, False if duplicate."""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("""
                    INSERT OR IGNORE INTO sigma_rules (
                        rule_id, title, description, status, level, author,
                        date, modified, references_json, tags_json,
                        logsource_json, detection_json, falsepositives_json,
                        fields_json, raw_yaml, source_file,
                        mitre_techniques_json, mitre_tactics_json,
                        hash, imported_at, enabled
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    rule.rule_id, rule.title, rule.description,
                    rule.status.value, rule.level.value, rule.author,
                    rule.date, rule.modified,
                    json.dumps(rule.references),
                    json.dumps(rule.tags),
                    json.dumps(rule.logsource),
                    json.dumps({
                        "selections": rule.detection.selections,
                        "filters": rule.detection.filters,
                        "condition": rule.detection.condition,
                    }),
                    json.dumps(rule.falsepositives),
                    json.dumps(rule.fields),
                    rule.raw_yaml, rule.source_file,
                    json.dumps(rule.mitre_techniques),
                    json.dumps(rule.mitre_tactics),
                    rule.hash, rule.imported_at,
                    1 if rule.enabled else 0,
                ))
                conn.commit()
                return conn.total_changes > 0
            finally:
                conn.close()

    def update(self, rule: SigmaRule) -> bool:
        """Update an existing rule."""
        with self._lock:
            conn = self._get_conn()
            try:
                cursor = conn.execute("""
                    UPDATE sigma_rules SET
                        title=?, description=?, status=?, level=?, author=?,
                        date=?, modified=?, references_json=?, tags_json=?,
                        logsource_json=?, detection_json=?, falsepositives_json=?,
                        fields_json=?, raw_yaml=?, source_file=?,
                        mitre_techniques_json=?, mitre_tactics_json=?,
                        hash=?, enabled=?, updated_at=CURRENT_TIMESTAMP
                    WHERE rule_id=?
                """, (
                    rule.title, rule.description,
                    rule.status.value, rule.level.value, rule.author,
                    rule.date, rule.modified,
                    json.dumps(rule.references),
                    json.dumps(rule.tags),
                    json.dumps(rule.logsource),
                    json.dumps({
                        "selections": rule.detection.selections,
                        "filters": rule.detection.filters,
                        "condition": rule.detection.condition,
                    }),
                    json.dumps(rule.falsepositives),
                    json.dumps(rule.fields),
                    rule.raw_yaml, rule.source_file,
                    json.dumps(rule.mitre_techniques),
                    json.dumps(rule.mitre_tactics),
                    rule.hash,
                    1 if rule.enabled else 0,
                    rule.rule_id,
                ))
                conn.commit()
                return cursor.rowcount > 0
            finally:
                conn.close()

    def get(self, rule_id: str) -> Optional[SigmaRule]:
        """Get a rule by ID."""
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM sigma_rules WHERE rule_id=?", (rule_id,)
            ).fetchone()
            if row:
                return self._row_to_rule(row)
            return None
        finally:
            conn.close()

    def delete(self, rule_id: str) -> bool:
        """Delete a rule by ID."""
        with self._lock:
            conn = self._get_conn()
            try:
                cursor = conn.execute(
                    "DELETE FROM sigma_rules WHERE rule_id=?", (rule_id,)
                )
                conn.commit()
                return cursor.rowcount > 0
            finally:
                conn.close()

    def list_rules(self, enabled_only: bool = False, level: str = "",
                   status: str = "", search: str = "",
                   limit: int = 100, offset: int = 0) -> List[SigmaRule]:
        """List rules with optional filters."""
        conn = self._get_conn()
        try:
            query = "SELECT * FROM sigma_rules WHERE 1=1"
            params: List[Any] = []

            if enabled_only:
                query += " AND enabled=1"
            if level:
                query += " AND level=?"
                params.append(level.lower())
            if status:
                query += " AND status=?"
                params.append(status.lower())
            if search:
                query += " AND (title LIKE ? OR description LIKE ? OR tags_json LIKE ?)"
                params.extend([f"%{search}%"] * 3)

            query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            rows = conn.execute(query, params).fetchall()
            return [self._row_to_rule(r) for r in rows]
        finally:
            conn.close()

    def count(self, enabled_only: bool = False) -> int:
        """Count rules in repository."""
        conn = self._get_conn()
        try:
            query = "SELECT COUNT(*) FROM sigma_rules"
            if enabled_only:
                query += " WHERE enabled=1"
            return conn.execute(query).fetchone()[0]
        finally:
            conn.close()

    def toggle_enabled(self, rule_id: str, enabled: bool) -> bool:
        """Enable or disable a rule."""
        with self._lock:
            conn = self._get_conn()
            try:
                cursor = conn.execute(
                    "UPDATE sigma_rules SET enabled=?, updated_at=CURRENT_TIMESTAMP WHERE rule_id=?",
                    (1 if enabled else 0, rule_id)
                )
                conn.commit()
                return cursor.rowcount > 0
            finally:
                conn.close()

    def get_by_hash(self, rule_hash: str) -> Optional[SigmaRule]:
        """Find a rule by its content hash."""
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM sigma_rules WHERE hash=?", (rule_hash,)
            ).fetchone()
            if row:
                return self._row_to_rule(row)
            return None
        finally:
            conn.close()

    def get_stats(self) -> Dict[str, Any]:
        """Get repository statistics."""
        conn = self._get_conn()
        try:
            total = conn.execute("SELECT COUNT(*) FROM sigma_rules").fetchone()[0]
            enabled = conn.execute("SELECT COUNT(*) FROM sigma_rules WHERE enabled=1").fetchone()[0]

            level_dist = {}
            for row in conn.execute("SELECT level, COUNT(*) FROM sigma_rules GROUP BY level"):
                level_dist[row[0]] = row[1]

            status_dist = {}
            for row in conn.execute("SELECT status, COUNT(*) FROM sigma_rules GROUP BY status"):
                status_dist[row[0]] = row[1]

            return {
                "total": total,
                "enabled": enabled,
                "disabled": total - enabled,
                "by_level": level_dist,
                "by_status": status_dist,
            }
        finally:
            conn.close()

    def import_rules(self, rules: List[SigmaRule]) -> Dict[str, int]:
        """Bulk import rules. Returns counts of added/skipped/errors."""
        result = {"added": 0, "skipped": 0, "errors": 0}
        for rule in rules:
            try:
                # Check for existing by hash
                if rule.hash and self.get_by_hash(rule.hash):
                    result["skipped"] += 1
                    continue
                if self.add(rule):
                    result["added"] += 1
                else:
                    result["skipped"] += 1
            except Exception as e:
                logger.error(f"Error importing rule {rule.title}: {e}")
                result["errors"] += 1
        return result

    def _row_to_rule(self, row: sqlite3.Row) -> SigmaRule:
        """Convert a database row to a SigmaRule object."""
        detection_data = json.loads(row["detection_json"])

        rule = SigmaRule.__new__(SigmaRule)
        rule.rule_id = row["rule_id"]
        rule.title = row["title"]
        rule.description = row["description"]
        rule.status = SigmaStatus.from_string(row["status"])
        rule.level = SigmaLevel.from_string(row["level"])
        rule.author = row["author"]
        rule.date = row["date"]
        rule.modified = row["modified"]
        rule.references = json.loads(row["references_json"])
        rule.tags = json.loads(row["tags_json"])
        rule.logsource = json.loads(row["logsource_json"])
        rule.detection = SigmaDetection(
            selections=detection_data.get("selections", {}),
            filters=detection_data.get("filters", {}),
            condition=detection_data.get("condition", ""),
        )
        rule.falsepositives = json.loads(row["falsepositives_json"])
        rule.fields = json.loads(row["fields_json"])
        rule.raw_yaml = row["raw_yaml"]
        rule.source_file = row["source_file"]
        rule.mitre_techniques = json.loads(row["mitre_techniques_json"])
        rule.mitre_tactics = json.loads(row["mitre_tactics_json"])
        rule.hash = row["hash"]
        rule.imported_at = row["imported_at"]
        rule.enabled = bool(row["enabled"])

        return rule


# ============================================================================
# Sigma Rule Engine (Orchestrator)
# ============================================================================

class SigmaEngine:
    """
    Main Sigma Rule Engine orchestrating parsing, storage, evaluation,
    and conversion of Sigma detection rules.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.repository = SigmaRepository(db_path=db_path)
        self.parser = SigmaParser()
        self.evaluator = DetectionEvaluator()
        self.wazuh_converter = WazuhConverter()
        self.suricata_converter = SuricataConverter()
        self._lock = threading.Lock()
        self._stats = {
            "rules_loaded": 0,
            "rules_evaluated": 0,
            "matches": 0,
            "evaluation_errors": 0,
            "conversions_wazuh": 0,
            "conversions_suricata": 0,
            "imports": 0,
        }
        logger.info("SigmaEngine initialized")

    @property
    def stats(self) -> Dict[str, Any]:
        repo_stats = self.repository.get_stats()
        return {**self._stats, "repository": repo_stats}

    def load_rule(self, yaml_content: str, source_file: str = "",
                  persist: bool = True) -> SigmaRule:
        """Parse and optionally persist a Sigma rule."""
        rule = self.parser.parse(yaml_content, source_file=source_file)
        if persist:
            self.repository.add(rule)
        self._stats["rules_loaded"] += 1
        return rule

    def load_file(self, filepath: str, persist: bool = True) -> SigmaRule:
        """Load a Sigma rule from a file."""
        rule = self.parser.parse_file(filepath)
        if persist:
            self.repository.add(rule)
        self._stats["rules_loaded"] += 1
        return rule

    def import_directory(self, dirpath: str, recursive: bool = True) -> Dict[str, int]:
        """Import all Sigma rules from a directory."""
        rules = self.parser.parse_directory(dirpath, recursive=recursive)
        result = self.repository.import_rules(rules)
        self._stats["imports"] += result["added"]
        self._stats["rules_loaded"] += result["added"]
        return result

    def evaluate(self, event: Dict[str, Any],
                 rules: Optional[List[SigmaRule]] = None) -> List[SigmaRule]:
        """
        Evaluate an event against rules and return matching rules.

        If rules is None, evaluates against all enabled rules in the repository.
        """
        if rules is None:
            rules = self.repository.list_rules(enabled_only=True, limit=10000)

        matches = []
        for rule in rules:
            try:
                if self.evaluator.evaluate_condition(
                    rule.detection.condition,
                    rule.detection.selections,
                    rule.detection.filters,
                    event,
                ):
                    matches.append(rule)
                    self._stats["matches"] += 1
            except Exception as e:
                logger.warning(f"Error evaluating rule '{rule.title}': {e}")
                self._stats["evaluation_errors"] += 1

            self._stats["rules_evaluated"] += 1

        return matches

    def evaluate_single(self, event: Dict[str, Any], rule: SigmaRule) -> bool:
        """Evaluate a single rule against an event."""
        try:
            self._stats["rules_evaluated"] += 1
            result = self.evaluator.evaluate_condition(
                rule.detection.condition,
                rule.detection.selections,
                rule.detection.filters,
                event,
            )
            if result:
                self._stats["matches"] += 1
            return result
        except Exception as e:
            logger.warning(f"Error evaluating rule '{rule.title}': {e}")
            self._stats["evaluation_errors"] += 1
            return False

    def convert_to_wazuh(self, rule_id: str = "", rule: SigmaRule = None) -> str:
        """Convert a rule to Wazuh XML format."""
        if rule is None:
            if not rule_id:
                raise ValueError("Either rule_id or rule must be provided")
            rule = self.repository.get(rule_id)
            if not rule:
                raise ValueError(f"Rule not found: {rule_id}")

        self._stats["conversions_wazuh"] += 1
        return self.wazuh_converter.convert(rule)

    def convert_to_suricata(self, rule_id: str = "", rule: SigmaRule = None) -> str:
        """Convert a rule to Suricata rule format."""
        if rule is None:
            if not rule_id:
                raise ValueError("Either rule_id or rule must be provided")
            rule = self.repository.get(rule_id)
            if not rule:
                raise ValueError(f"Rule not found: {rule_id}")

        self._stats["conversions_suricata"] += 1
        return self.suricata_converter.convert(rule)

    def export_all_wazuh(self, enabled_only: bool = True) -> str:
        """Export all rules as a Wazuh rules XML file."""
        rules = self.repository.list_rules(enabled_only=enabled_only, limit=100000)
        self._stats["conversions_wazuh"] += len(rules)
        return self.wazuh_converter.convert_batch(rules)

    def export_all_suricata(self, enabled_only: bool = True) -> str:
        """Export all rules as a Suricata rules file."""
        rules = self.repository.list_rules(enabled_only=enabled_only, limit=100000)
        self._stats["conversions_suricata"] += len(rules)
        return self.suricata_converter.convert_batch(rules)

    def search_rules(self, query: str, level: str = "",
                     status: str = "", limit: int = 50) -> List[SigmaRule]:
        """Search rules by text, level, or status."""
        return self.repository.list_rules(
            search=query, level=level, status=status, limit=limit
        )

    def get_rule(self, rule_id: str) -> Optional[SigmaRule]:
        """Get a specific rule by ID."""
        return self.repository.get(rule_id)

    def delete_rule(self, rule_id: str) -> bool:
        """Delete a rule from the repository."""
        return self.repository.delete(rule_id)

    def toggle_rule(self, rule_id: str, enabled: bool) -> bool:
        """Enable or disable a rule."""
        return self.repository.toggle_enabled(rule_id, enabled)

    def update_rule(self, rule: SigmaRule) -> bool:
        """Update an existing rule."""
        return self.repository.update(rule)


# ============================================================================
# Utility Functions
# ============================================================================

def _xml_escape(s: str) -> str:
    """Escape special characters for XML."""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def _suricata_escape(s: str) -> str:
    """Escape characters for Suricata rule strings."""
    return str(s).replace('"', '\\"').replace(';', '\\;')


# ============================================================================
# Flask Blueprint
# ============================================================================

def create_sigma_blueprint(engine: Optional["SigmaEngine"] = None):
    """Create a Flask Blueprint for Sigma Engine API."""
    try:
        from flask import Blueprint, request, jsonify
    except ImportError:
        logger.warning("Flask not available, skipping blueprint creation")
        return None

    bp = Blueprint("sigma_engine", __name__, url_prefix="/api/v1/soc/sigma")

    def _get_engine():
        return engine or get_sigma_engine()

    @bp.route("/status", methods=["GET"])
    def status():
        eng = _get_engine()
        return jsonify({"status": "ok", "stats": eng.stats})

    @bp.route("/rules", methods=["GET"])
    def list_rules():
        eng = _get_engine()
        search = request.args.get("search", "")
        level = request.args.get("level", "")
        rule_status = request.args.get("status", "")
        enabled_only = request.args.get("enabled_only", "false").lower() == "true"
        limit = min(int(request.args.get("limit", 50)), 500)
        offset = int(request.args.get("offset", 0))

        rules = eng.repository.list_rules(
            enabled_only=enabled_only, level=level,
            status=rule_status, search=search,
            limit=limit, offset=offset,
        )
        return jsonify({
            "count": len(rules),
            "rules": [r.to_dict() for r in rules],
        })

    @bp.route("/rules/<rule_id>", methods=["GET"])
    def get_rule(rule_id):
        eng = _get_engine()
        rule = eng.get_rule(rule_id)
        if not rule:
            return jsonify({"error": "Rule not found"}), 404
        return jsonify(rule.to_dict())

    @bp.route("/rules/<rule_id>", methods=["DELETE"])
    def delete_rule(rule_id):
        eng = _get_engine()
        if eng.delete_rule(rule_id):
            return jsonify({"status": "deleted"})
        return jsonify({"error": "Rule not found"}), 404

    @bp.route("/rules/<rule_id>/toggle", methods=["POST"])
    def toggle_rule(rule_id):
        eng = _get_engine()
        data = request.get_json(silent=True) or {}
        enabled = data.get("enabled", True)
        if eng.toggle_rule(rule_id, enabled):
            return jsonify({"status": "updated", "enabled": enabled})
        return jsonify({"error": "Rule not found"}), 404

    @bp.route("/load", methods=["POST"])
    def load_rule():
        eng = _get_engine()
        data = request.get_json(silent=True)
        if not data or "yaml" not in data:
            return jsonify({"error": "Missing 'yaml' field"}), 400
        try:
            rule = eng.load_rule(data["yaml"], source_file=data.get("source", ""))
            return jsonify({"status": "loaded", "rule": rule.to_dict()})
        except SigmaParseError as e:
            return jsonify({"error": str(e)}), 400

    @bp.route("/evaluate", methods=["POST"])
    def evaluate():
        eng = _get_engine()
        data = request.get_json(silent=True)
        if not data or "event" not in data:
            return jsonify({"error": "Missing 'event' field"}), 400

        rule_ids = data.get("rule_ids")
        rules = None
        if rule_ids:
            rules = [eng.get_rule(rid) for rid in rule_ids]
            rules = [r for r in rules if r is not None]

        matches = eng.evaluate(data["event"], rules=rules)
        return jsonify({
            "matches": len(matches),
            "rules": [r.to_dict() for r in matches],
        })

    @bp.route("/convert/wazuh/<rule_id>", methods=["GET"])
    def convert_wazuh(rule_id):
        eng = _get_engine()
        try:
            xml = eng.convert_to_wazuh(rule_id=rule_id)
            return jsonify({"rule_id": rule_id, "format": "wazuh", "output": xml})
        except ValueError as e:
            return jsonify({"error": str(e)}), 404

    @bp.route("/convert/suricata/<rule_id>", methods=["GET"])
    def convert_suricata(rule_id):
        eng = _get_engine()
        try:
            output = eng.convert_to_suricata(rule_id=rule_id)
            return jsonify({"rule_id": rule_id, "format": "suricata", "output": output})
        except ValueError as e:
            return jsonify({"error": str(e)}), 404

    @bp.route("/export/wazuh", methods=["GET"])
    def export_wazuh():
        eng = _get_engine()
        xml = eng.export_all_wazuh()
        return jsonify({"format": "wazuh", "output": xml})

    @bp.route("/export/suricata", methods=["GET"])
    def export_suricata():
        eng = _get_engine()
        output = eng.export_all_suricata()
        return jsonify({"format": "suricata", "output": output})

    return bp


# ============================================================================
# Global Singleton
# ============================================================================

_sigma_engine_instance: Optional[SigmaEngine] = None
_sigma_engine_lock = threading.Lock()


def get_sigma_engine(db_path: Optional[str] = None) -> SigmaEngine:
    """Get or create the global SigmaEngine singleton."""
    global _sigma_engine_instance
    if _sigma_engine_instance is None:
        with _sigma_engine_lock:
            if _sigma_engine_instance is None:
                _sigma_engine_instance = SigmaEngine(db_path=db_path)
    return _sigma_engine_instance


# ============================================================================
# Module Exports
# ============================================================================

__all__ = [
    "SigmaStatus",
    "SigmaLevel",
    "SigmaDetection",
    "SigmaRule",
    "SigmaParseError",
    "SigmaParser",
    "DetectionEvaluator",
    "WazuhConverter",
    "SuricataConverter",
    "SigmaRepository",
    "SigmaEngine",
    "create_sigma_blueprint",
    "get_sigma_engine",
    "SIGMA_LOGSOURCE_FIELDS",
    "SIGMA_MODIFIERS",
]
