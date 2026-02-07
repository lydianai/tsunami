#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    MITRE ATT&CK Module Tests
    Tests for TSUNAMI v5.0 MITRE ATT&CK Integration
================================================================================
"""

import pytest
import json
import sys
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.mitre_attack import (
    MITREAttackData,
    TechniqueMapper,
    DefenseAnalyzer,
    NavigatorGenerator,
    get_attack_data,
    get_technique_mapper,
    get_defense_analyzer,
    get_navigator_generator
)
from modules.mitre_attack.attack_data import Technique, Tactic, Mitigation
from modules.mitre_attack.technique_mapper import EventType, ConfidenceLevel, TechniqueMatch
from modules.mitre_attack.defense_analyzer import DefenseCategory, DefensePriority
from modules.mitre_attack.attack_navigator import ColorScheme, NavigatorLayer


class TestMITREAttackData:
    """Tests for ATT&CK data loading and parsing"""

    @pytest.fixture
    def attack_data(self):
        """Get ATT&CK data instance"""
        data = get_attack_data()
        if not data.is_loaded():
            data.load_data()
        return data

    def test_data_loads_successfully(self, attack_data):
        """Test that ATT&CK data loads from MITRE"""
        assert attack_data.is_loaded(), "ATT&CK data should be loaded"

    def test_techniques_exist(self, attack_data):
        """Test that techniques are parsed"""
        techniques = attack_data.list_techniques()
        assert len(techniques) > 100, "Should have 100+ techniques"

    def test_get_technique_by_id(self, attack_data):
        """Test technique lookup by ID"""
        # T1059 - Command and Scripting Interpreter
        technique = attack_data.get_technique('T1059')
        assert technique is not None
        assert technique.id == 'T1059'
        assert 'Command' in technique.name
        assert len(technique.tactics) > 0

    def test_get_subtechnique(self, attack_data):
        """Test subtechnique lookup"""
        # T1059.001 - PowerShell
        technique = attack_data.get_technique('T1059.001')
        assert technique is not None
        assert technique.is_subtechnique
        assert technique.parent_id == 'T1059'
        assert 'PowerShell' in technique.name

    def test_tactics_exist(self, attack_data):
        """Test tactics are parsed"""
        tactics = attack_data.list_tactics()
        assert len(tactics) == 14, "Should have 14 tactics"

        # Check order
        assert tactics[0].shortname == 'reconnaissance'
        assert tactics[-1].shortname == 'impact'

    def test_mitigations_exist(self, attack_data):
        """Test mitigations are parsed"""
        mitigations = attack_data.list_mitigations()
        assert len(mitigations) > 30, "Should have 30+ mitigations"

    def test_get_mitigation_by_id(self, attack_data):
        """Test mitigation lookup"""
        mitigation = attack_data.get_mitigation('M1047')
        assert mitigation is not None
        assert 'Audit' in mitigation.name

    def test_groups_exist(self, attack_data):
        """Test threat groups are parsed"""
        groups = attack_data.list_groups()
        assert len(groups) > 50, "Should have 50+ groups"

    def test_get_group_by_name(self, attack_data):
        """Test group lookup by name"""
        group = attack_data.get_group('APT28')
        assert group is not None
        assert 'APT28' in group.name or 'APT28' in group.aliases

    def test_software_exists(self, attack_data):
        """Test software is parsed"""
        software = attack_data.list_software()
        assert len(software) > 100, "Should have 100+ software entries"

    def test_techniques_by_tactic(self, attack_data):
        """Test filtering techniques by tactic"""
        execution_techs = attack_data.get_techniques_by_tactic('execution')
        assert len(execution_techs) > 10, "Should have 10+ execution techniques"

        for tech in execution_techs:
            assert 'execution' in tech.tactics

    def test_techniques_by_platform(self, attack_data):
        """Test filtering techniques by platform"""
        windows_techs = attack_data.get_techniques_by_platform('Windows')
        linux_techs = attack_data.get_techniques_by_platform('Linux')

        assert len(windows_techs) > 100, "Should have 100+ Windows techniques"
        assert len(linux_techs) > 50, "Should have 50+ Linux techniques"

    def test_search_techniques(self, attack_data):
        """Test technique search"""
        results = attack_data.search_techniques('powershell', limit=10)
        assert len(results) > 0

        # First result should be highly relevant
        tech, score = results[0]
        assert 'PowerShell' in tech.name or 'powershell' in tech.description.lower()

    def test_mitigations_for_technique(self, attack_data):
        """Test getting mitigations for technique"""
        mitigations = attack_data.get_mitigations_for_technique('T1059')
        assert len(mitigations) > 0, "T1059 should have mitigations"

    def test_groups_using_technique(self, attack_data):
        """Test getting groups using technique"""
        groups = attack_data.get_groups_using_technique('T1059')
        assert len(groups) > 0, "T1059 should be used by groups"

    def test_statistics(self, attack_data):
        """Test statistics generation"""
        stats = attack_data.get_statistics()

        assert stats['data_loaded'] is True
        assert stats['counts']['tactics'] == 14
        assert stats['counts']['techniques'] > 100
        assert len(stats['platforms']) > 0


class TestTechniqueMapper:
    """Tests for technique mapping"""

    @pytest.fixture
    def mapper(self):
        """Get mapper instance"""
        return get_technique_mapper()

    def test_map_process_event(self, mapper):
        """Test mapping process creation event"""
        event = {
            'event_type': 'process_creation',
            'process_name': 'powershell.exe',
            'command_line': 'powershell.exe -enc SGVsbG8gV29ybGQ='
        }

        mapping = mapper.map_event(event)
        assert len(mapping.matches) > 0

        # Should detect T1059.001 (PowerShell)
        tech_ids = [m.technique_id for m in mapping.matches]
        assert 'T1059.001' in tech_ids

    def test_map_mimikatz_event(self, mapper):
        """Test mapping credential dumping event"""
        event = {
            'event_type': 'process_creation',
            'process_name': 'mimikatz.exe',
            'command_line': 'mimikatz.exe sekurlsa::logonpasswords'
        }

        mapping = mapper.map_event(event)
        assert len(mapping.matches) > 0

        # Should detect T1003.001 (LSASS Memory)
        tech_ids = [m.technique_id for m in mapping.matches]
        assert 'T1003.001' in tech_ids

    def test_map_lateral_movement_event(self, mapper):
        """Test mapping lateral movement event"""
        event = {
            'event_type': 'process_creation',
            'process_name': 'psexec.exe',
            'command_line': 'psexec.exe \\\\server cmd.exe'
        }

        mapping = mapper.map_event(event)
        assert len(mapping.matches) > 0

        tech_ids = [m.technique_id for m in mapping.matches]
        assert any(t in tech_ids for t in ['T1021.002', 'T1569.002'])

    def test_map_cve(self, mapper):
        """Test CVE to technique mapping"""
        # Log4Shell
        matches = mapper.map_cve('CVE-2021-44228')
        assert len(matches) > 0

        tech_ids = [m.technique_id for m in matches]
        assert 'T1190' in tech_ids  # Exploit Public-Facing Application

    def test_map_cve_zerologon(self, mapper):
        """Test Zerologon CVE mapping"""
        matches = mapper.map_cve('CVE-2020-1472')
        assert len(matches) > 0

        tech_ids = [m.technique_id for m in matches]
        assert 'T1068' in tech_ids  # Exploitation for Privilege Escalation

    def test_map_stix_pattern(self, mapper):
        """Test STIX pattern mapping"""
        pattern = "[process:name = 'powershell.exe']"
        matches = mapper.map_stix_pattern(pattern)

        assert len(matches) > 0
        tech_ids = [m.technique_id for m in matches]
        assert 'T1059.001' in tech_ids

    def test_confidence_levels(self, mapper):
        """Test confidence level assignment"""
        event = {
            'event_type': 'process_creation',
            'process_name': 'cmd.exe',
            'command_line': 'cmd.exe /c whoami'
        }

        mapping = mapper.map_event(event)
        for match in mapping.matches:
            assert match.confidence >= 0.0
            assert match.confidence <= 1.0
            assert match.confidence_level in ConfidenceLevel

    def test_coverage_report(self, mapper):
        """Test coverage report generation"""
        # Create some test mappings
        events = [
            {'event_type': 'process_creation', 'process_name': 'powershell.exe'},
            {'event_type': 'process_creation', 'process_name': 'cmd.exe'},
            {'event_type': 'process_creation', 'process_name': 'wmic.exe'}
        ]

        mappings = [mapper.map_event(e) for e in events]
        report = mapper.generate_coverage_report(mappings)

        assert 'summary' in report
        assert 'detected_techniques' in report
        assert 'tactic_coverage' in report


class TestDefenseAnalyzer:
    """Tests for defense analysis"""

    @pytest.fixture
    def analyzer(self):
        """Get analyzer instance"""
        return get_defense_analyzer()

    def test_list_defenses(self, analyzer):
        """Test listing defenses"""
        defenses = analyzer.list_defenses()
        assert len(defenses) > 10, "Should have 10+ defenses"

    def test_list_defenses_by_category(self, analyzer):
        """Test filtering defenses by category"""
        harden = analyzer.list_defenses(category=DefenseCategory.HARDEN)
        detect = analyzer.list_defenses(category=DefenseCategory.DETECT)

        assert len(harden) > 0
        assert len(detect) > 0

        for d in harden:
            assert d.category == DefenseCategory.HARDEN

    def test_get_defenses_for_technique(self, analyzer):
        """Test getting defenses for technique"""
        defenses = analyzer.get_defenses_for_technique('T1059')
        assert len(defenses) > 0, "T1059 should have defenses"

    def test_analyze_coverage(self, analyzer):
        """Test coverage analysis for technique"""
        coverage = analyzer.analyze_coverage('T1059')

        assert coverage.technique_id == 'T1059'
        assert 0 <= coverage.coverage_score <= 1.0
        assert isinstance(coverage.defenses, list)
        assert isinstance(coverage.mitigations, list)

    def test_analyze_gaps(self, analyzer):
        """Test gap analysis"""
        technique_ids = ['T1059', 'T1003', 'T1055', 'T1078']
        gaps = analyzer.analyze_gaps(technique_ids)

        # Should identify some gaps
        for gap in gaps:
            assert gap.technique_id in technique_ids
            assert gap.severity in DefensePriority

    def test_recommend_mitigations(self, analyzer):
        """Test mitigation recommendations"""
        technique_ids = ['T1059', 'T1003', 'T1055']
        recommendations = analyzer.recommend_mitigations(technique_ids, max_recommendations=5)

        assert len(recommendations) > 0
        assert len(recommendations) <= 5

        for rec in recommendations:
            assert rec.priority in DefensePriority
            assert len(rec.techniques_addressed) > 0

    def test_generate_gap_report(self, analyzer):
        """Test full gap report generation"""
        technique_ids = ['T1059', 'T1003', 'T1055']
        report = analyzer.generate_gap_report(technique_ids)

        assert 'summary' in report
        assert 'coverage_details' in report
        assert 'gaps_by_severity' in report
        assert 'top_recommendations' in report


class TestNavigatorGenerator:
    """Tests for ATT&CK Navigator layer generation"""

    @pytest.fixture
    def generator(self):
        """Get generator instance"""
        return get_navigator_generator()

    def test_create_detection_layer(self, generator):
        """Test detection layer creation"""
        detections = {
            'T1059': 10,
            'T1059.001': 5,
            'T1003': 3,
            'T1003.001': 2,
            'T1055': 1
        }

        layer = generator.create_detection_layer(
            detections=detections,
            name='Test Detection Layer'
        )

        assert layer.name == 'Test Detection Layer'
        assert len(layer.techniques) > 0

        # Verify JSON is valid
        json_str = layer.to_json()
        parsed = json.loads(json_str)
        assert parsed['name'] == 'Test Detection Layer'
        assert len(parsed['techniques']) > 0

    def test_create_coverage_layer(self, generator):
        """Test coverage layer creation"""
        coverage = {
            'T1059': 0.8,
            'T1003': 0.5,
            'T1055': 0.2,
            'T1078': 0.0
        }

        layer = generator.create_coverage_layer(
            coverage=coverage,
            name='Test Coverage Layer'
        )

        assert layer.name == 'Test Coverage Layer'
        assert len(layer.techniques) > 0

    def test_create_group_layer(self, generator):
        """Test group layer creation"""
        layer = generator.create_group_layer('APT28')

        if layer:  # APT28 should exist
            assert 'APT28' in layer.name
            assert len(layer.techniques) > 0

    def test_create_comparison_layer(self, generator):
        """Test comparison layer creation"""
        layer_a = {'T1059': 5, 'T1003': 3}
        layer_b = {'T1059': 2, 'T1055': 4}

        layer = generator.create_comparison_layer(
            layer_a=layer_a,
            layer_b=layer_b,
            name='Comparison Test',
            label_a='Set A',
            label_b='Set B'
        )

        assert layer.name == 'Comparison Test'
        assert len(layer.techniques) == 3  # T1059 (both), T1003 (A only), T1055 (B only)

    def test_record_and_get_trends(self, generator):
        """Test trend tracking"""
        from datetime import timedelta

        # Record some detections
        now = datetime.now()
        generator.record_detection('T1059', now - timedelta(days=5), count=2)
        generator.record_detection('T1059', now - timedelta(days=3), count=3)
        generator.record_detection('T1059', now, count=5)

        trends = generator.get_trends(days=30)

        assert 'increasing' in trends
        assert 'decreasing' in trends
        assert 'stable' in trends

    def test_layer_export(self, generator):
        """Test layer export to JSON"""
        detections = {'T1059': 5, 'T1003': 3}
        layer = generator.create_detection_layer(detections)

        # Export should return valid JSON
        json_str = layer.to_json()
        parsed = json.loads(json_str)

        assert 'name' in parsed
        assert 'versions' in parsed
        assert 'techniques' in parsed
        assert parsed['domain'] == 'enterprise-attack'


class TestAPIRoutes:
    """Tests for API routes (requires Flask test client)"""

    @pytest.fixture
    def client(self):
        """Get Flask test client"""
        try:
            from flask import Flask
            from modules.mitre_attack.api_routes import mitre_bp, init_data

            app = Flask(__name__)
            app.config['TESTING'] = True
            app.register_blueprint(mitre_bp)

            # Initialize data
            init_data()

            return app.test_client()
        except ImportError:
            pytest.skip("Flask not available")

    def test_health_endpoint(self, client):
        """Test health check endpoint"""
        response = client.get('/api/v5/mitre/health')
        assert response.status_code == 200

        data = response.get_json()
        assert data['success'] is True
        assert 'status' in data['data']

    def test_techniques_endpoint(self, client):
        """Test techniques listing endpoint"""
        response = client.get('/api/v5/mitre/techniques?limit=10')
        assert response.status_code == 200

        data = response.get_json()
        assert data['success'] is True
        assert 'techniques' in data['data']
        assert len(data['data']['techniques']) <= 10

    def test_tactics_endpoint(self, client):
        """Test tactics listing endpoint"""
        response = client.get('/api/v5/mitre/tactics')
        assert response.status_code == 200

        data = response.get_json()
        assert data['success'] is True
        assert len(data['data']['tactics']) == 14

    def test_search_endpoint(self, client):
        """Test search endpoint"""
        response = client.get('/api/v5/mitre/search?q=powershell')
        assert response.status_code == 200

        data = response.get_json()
        assert data['success'] is True
        assert len(data['data']['results']) > 0

    def test_map_event_endpoint(self, client):
        """Test event mapping endpoint"""
        response = client.post(
            '/api/v5/mitre/map',
            json={
                'event_type': 'process_creation',
                'process_name': 'powershell.exe'
            }
        )
        assert response.status_code == 200

        data = response.get_json()
        assert data['success'] is True
        assert 'matches' in data['data']

    def test_map_cve_endpoint(self, client):
        """Test CVE mapping endpoint"""
        response = client.post(
            '/api/v5/mitre/map/cve',
            json={'cve_id': 'CVE-2021-44228'}
        )
        assert response.status_code == 200

        data = response.get_json()
        assert data['success'] is True
        assert 'cve_mappings' in data['data']


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
