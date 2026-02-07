#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI v5.0 EVENT PIPELINE
    Security event processing pipeline
================================================================================

    Features:
    - Receive events from all sources
    - Enrich with threat intelligence
    - Classify with AI/ML
    - Correlate with XDR
    - Trigger SOAR responses
    - Update MITRE mappings

================================================================================
"""

import asyncio
import logging
import threading
import queue
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set
from collections import defaultdict
import json

logger = logging.getLogger("event_pipeline")


class EventType(Enum):
    """Types of security events"""
    NETWORK = "network"
    ENDPOINT = "endpoint"
    APPLICATION = "application"
    IDENTITY = "identity"
    CLOUD = "cloud"
    THREAT_INTEL = "threat_intel"
    VULNERABILITY = "vulnerability"
    COMPLIANCE = "compliance"
    CUSTOM = "custom"


class EventPriority(Enum):
    """Event processing priority"""
    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3
    INFO = 4


class PipelineStage(Enum):
    """Pipeline processing stages"""
    INGESTION = "ingestion"
    NORMALIZATION = "normalization"
    ENRICHMENT = "enrichment"
    CLASSIFICATION = "classification"
    CORRELATION = "correlation"
    RESPONSE = "response"
    STORAGE = "storage"


@dataclass
class SecurityEvent:
    """Raw security event from any source"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: EventType = EventType.CUSTOM
    source: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    priority: EventPriority = EventPriority.MEDIUM
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "event_type": self.event_type.value,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "raw_data": self.raw_data,
            "priority": self.priority.value,
            "metadata": self.metadata
        }


@dataclass
class EnrichedEvent:
    """Security event enriched with additional context"""
    original_event: SecurityEvent
    threat_intel: Dict[str, Any] = field(default_factory=dict)
    mitre_techniques: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    ai_classification: Dict[str, Any] = field(default_factory=dict)
    correlation_ids: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    iocs: List[Dict[str, str]] = field(default_factory=list)
    geo_data: Dict[str, Any] = field(default_factory=dict)
    user_context: Dict[str, Any] = field(default_factory=dict)
    asset_context: Dict[str, Any] = field(default_factory=dict)
    enrichment_timestamp: datetime = field(default_factory=datetime.now)
    processing_stages: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "original_event": self.original_event.to_dict(),
            "threat_intel": self.threat_intel,
            "mitre_techniques": self.mitre_techniques,
            "mitre_tactics": self.mitre_tactics,
            "ai_classification": self.ai_classification,
            "correlation_ids": self.correlation_ids,
            "risk_score": self.risk_score,
            "iocs": self.iocs,
            "geo_data": self.geo_data,
            "user_context": self.user_context,
            "asset_context": self.asset_context,
            "enrichment_timestamp": self.enrichment_timestamp.isoformat(),
            "processing_stages": self.processing_stages
        }


class EventProcessor:
    """Base class for event processors in the pipeline"""

    def __init__(self, name: str):
        self.name = name
        self.processed_count = 0
        self.error_count = 0
        self.enabled = True

    def process(self, event: EnrichedEvent) -> EnrichedEvent:
        """Process an event. Override in subclasses."""
        raise NotImplementedError

    async def process_async(self, event: EnrichedEvent) -> EnrichedEvent:
        """Async version of process"""
        return self.process(event)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "processed": self.processed_count,
            "errors": self.error_count,
            "enabled": self.enabled
        }


class ThreatIntelEnricher(EventProcessor):
    """Enrich events with threat intelligence"""

    def __init__(self):
        super().__init__("threat_intel_enricher")
        self._threat_intel_module = None

    def _get_threat_intel(self):
        """Lazy load threat intel module"""
        if self._threat_intel_module is None:
            try:
                from .v5_orchestrator import get_orchestrator
                orchestrator = get_orchestrator()
                self._threat_intel_module = orchestrator.get_module("threat_intel")
            except Exception as e:
                logger.warning(f"Could not load threat_intel module: {e}")
        return self._threat_intel_module

    def process(self, event: EnrichedEvent) -> EnrichedEvent:
        """Enrich event with threat intelligence"""
        if not self.enabled:
            return event

        try:
            self.processed_count += 1
            event.processing_stages.append(PipelineStage.ENRICHMENT.value)

            threat_intel = self._get_threat_intel()
            if not threat_intel:
                return event

            # Extract IOCs from event
            iocs_to_check = self._extract_iocs(event.original_event.raw_data)

            # Check against threat intel
            try:
                correlator = threat_intel.get_correlator()
                if correlator:
                    for ioc_type, ioc_value in iocs_to_check:
                        result = correlator.check_indicator(ioc_value, ioc_type)
                        if result and result.get("matched"):
                            event.threat_intel[ioc_value] = result
                            event.iocs.append({"type": ioc_type, "value": ioc_value})
                            # Increase risk score for threat intel matches
                            event.risk_score += result.get("severity_score", 10)
            except Exception as e:
                logger.warning(f"Threat intel correlation error: {e}")

            return event

        except Exception as e:
            self.error_count += 1
            logger.error(f"Error in ThreatIntelEnricher: {e}")
            return event

    def _extract_iocs(self, data: Dict[str, Any]) -> List[tuple]:
        """Extract potential IOCs from event data"""
        import re
        iocs = []

        data_str = json.dumps(data)

        # Extract IPs
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        for ip in re.findall(ip_pattern, data_str):
            if not ip.startswith(('10.', '172.', '192.168.', '127.')):
                iocs.append(("ip", ip))

        # Extract domains
        domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        for domain in re.findall(domain_pattern, data_str.lower()):
            if not domain.endswith(('.local', '.internal', '.lan')):
                iocs.append(("domain", domain))

        # Extract hashes (MD5, SHA1, SHA256)
        hash_patterns = [
            (r'\b[a-fA-F0-9]{32}\b', "md5"),
            (r'\b[a-fA-F0-9]{40}\b', "sha1"),
            (r'\b[a-fA-F0-9]{64}\b', "sha256")
        ]
        for pattern, hash_type in hash_patterns:
            for hash_val in re.findall(pattern, data_str):
                iocs.append((hash_type, hash_val.lower()))

        return iocs[:50]  # Limit to 50 IOCs per event


class MITREMapper(EventProcessor):
    """Map events to MITRE ATT&CK techniques"""

    def __init__(self):
        super().__init__("mitre_mapper")
        self._mitre_module = None

    def _get_mitre(self):
        """Lazy load MITRE module"""
        if self._mitre_module is None:
            try:
                from .v5_orchestrator import get_orchestrator
                orchestrator = get_orchestrator()
                self._mitre_module = orchestrator.get_module("mitre_attack")
            except Exception as e:
                logger.warning(f"Could not load mitre_attack module: {e}")
        return self._mitre_module

    def process(self, event: EnrichedEvent) -> EnrichedEvent:
        """Map event to MITRE techniques"""
        if not self.enabled:
            return event

        try:
            self.processed_count += 1

            mitre = self._get_mitre()
            if not mitre:
                return event

            # Get technique mapper
            try:
                mapper = mitre.get_technique_mapper()
                if mapper:
                    # Map based on event data
                    matches = mapper.map_event(event.original_event.raw_data)
                    if matches:
                        for match in matches:
                            if hasattr(match, 'technique_id'):
                                event.mitre_techniques.append(match.technique_id)
                            if hasattr(match, 'tactic'):
                                event.mitre_tactics.append(match.tactic)
            except Exception as e:
                logger.warning(f"MITRE mapping error: {e}")

            return event

        except Exception as e:
            self.error_count += 1
            logger.error(f"Error in MITREMapper: {e}")
            return event


class AIClassifier(EventProcessor):
    """Classify events using AI/ML models"""

    def __init__(self):
        super().__init__("ai_classifier")
        self._ai_module = None

    def _get_ai(self):
        """Lazy load AI prediction module"""
        if self._ai_module is None:
            try:
                from .v5_orchestrator import get_orchestrator
                orchestrator = get_orchestrator()
                self._ai_module = orchestrator.get_module("ai_prediction")
            except Exception as e:
                logger.warning(f"Could not load ai_prediction module: {e}")
        return self._ai_module

    def process(self, event: EnrichedEvent) -> EnrichedEvent:
        """Classify event using AI"""
        if not self.enabled:
            return event

        try:
            self.processed_count += 1
            event.processing_stages.append(PipelineStage.CLASSIFICATION.value)

            ai = self._get_ai()
            if not ai:
                return event

            try:
                # Use threat predictor for classification
                predictor = ai.ThreatPredictor()

                # Extract features from event
                features = self._extract_features(event)

                # Get prediction
                prediction = predictor.predict(features)
                if prediction:
                    event.ai_classification = {
                        "threat_type": prediction.get("type", "unknown"),
                        "confidence": prediction.get("confidence", 0.0),
                        "severity": prediction.get("severity", "medium"),
                        "is_malicious": prediction.get("is_malicious", False)
                    }

                    # Adjust risk score based on AI classification
                    if event.ai_classification.get("is_malicious"):
                        event.risk_score += 30 * event.ai_classification.get("confidence", 0.5)

            except Exception as e:
                logger.warning(f"AI classification error: {e}")

            return event

        except Exception as e:
            self.error_count += 1
            logger.error(f"Error in AIClassifier: {e}")
            return event

    def _extract_features(self, event: EnrichedEvent) -> Dict[str, Any]:
        """Extract ML features from event"""
        return {
            "event_type": event.original_event.event_type.value,
            "source": event.original_event.source,
            "priority": event.original_event.priority.value,
            "has_threat_intel": len(event.threat_intel) > 0,
            "ioc_count": len(event.iocs),
            "mitre_count": len(event.mitre_techniques),
            "raw_data": event.original_event.raw_data
        }


class XDRCorrelator(EventProcessor):
    """Correlate events using XDR engine"""

    def __init__(self):
        super().__init__("xdr_correlator")
        self._xdr_module = None

    def _get_xdr(self):
        """Lazy load SOAR/XDR module"""
        if self._xdr_module is None:
            try:
                from .v5_orchestrator import get_orchestrator
                orchestrator = get_orchestrator()
                self._xdr_module = orchestrator.get_module("soar_xdr")
            except Exception as e:
                logger.warning(f"Could not load soar_xdr module: {e}")
        return self._xdr_module

    def process(self, event: EnrichedEvent) -> EnrichedEvent:
        """Correlate event with XDR"""
        if not self.enabled:
            return event

        try:
            self.processed_count += 1
            event.processing_stages.append(PipelineStage.CORRELATION.value)

            xdr = self._get_xdr()
            if not xdr:
                return event

            try:
                correlation_engine = xdr.get_correlation_engine()
                if correlation_engine:
                    # Submit event for correlation
                    correlation_result = correlation_engine.correlate(event.to_dict())
                    if correlation_result:
                        event.correlation_ids = correlation_result.get("related_events", [])

                        # If part of attack chain, increase risk
                        if correlation_result.get("attack_chain"):
                            event.risk_score += 25

            except Exception as e:
                logger.warning(f"XDR correlation error: {e}")

            return event

        except Exception as e:
            self.error_count += 1
            logger.error(f"Error in XDRCorrelator: {e}")
            return event


class SOARResponder(EventProcessor):
    """Trigger SOAR playbooks based on events"""

    def __init__(self):
        super().__init__("soar_responder")
        self._soar_module = None
        self.risk_threshold = 50.0  # Minimum risk score to trigger SOAR

    def _get_soar(self):
        """Lazy load SOAR module"""
        if self._soar_module is None:
            try:
                from .v5_orchestrator import get_orchestrator
                orchestrator = get_orchestrator()
                self._soar_module = orchestrator.get_module("soar_xdr")
            except Exception as e:
                logger.warning(f"Could not load soar_xdr module: {e}")
        return self._soar_module

    def process(self, event: EnrichedEvent) -> EnrichedEvent:
        """Trigger SOAR response if needed"""
        if not self.enabled:
            return event

        try:
            self.processed_count += 1
            event.processing_stages.append(PipelineStage.RESPONSE.value)

            # Only respond to high-risk events
            if event.risk_score < self.risk_threshold:
                return event

            soar = self._get_soar()
            if not soar:
                return event

            try:
                playbook_engine = soar.get_playbook_engine()
                if playbook_engine:
                    # Find matching playbook
                    playbook = playbook_engine.find_matching_playbook(event.to_dict())
                    if playbook:
                        # Execute playbook
                        execution = playbook_engine.execute(playbook, event.to_dict())
                        event.metadata["soar_execution_id"] = execution.get("id")
                        logger.info(f"Triggered playbook for event {event.original_event.id}")

            except Exception as e:
                logger.warning(f"SOAR response error: {e}")

            return event

        except Exception as e:
            self.error_count += 1
            logger.error(f"Error in SOARResponder: {e}")
            return event


class EventPipeline:
    """
    Central event processing pipeline.
    Events flow through multiple stages of enrichment and processing.
    """

    def __init__(self):
        self.processors: List[EventProcessor] = []
        self._event_queue: queue.PriorityQueue = queue.PriorityQueue()
        self._running = False
        self._worker_threads: List[threading.Thread] = []
        self._processed_count = 0
        self._error_count = 0
        self._lock = threading.Lock()

        # Initialize default processors
        self._setup_default_processors()

    def _setup_default_processors(self):
        """Setup default event processors"""
        self.processors = [
            ThreatIntelEnricher(),
            MITREMapper(),
            AIClassifier(),
            XDRCorrelator(),
            SOARResponder()
        ]
        logger.info(f"Pipeline initialized with {len(self.processors)} processors")

    def add_processor(self, processor: EventProcessor, index: Optional[int] = None) -> None:
        """Add a processor to the pipeline"""
        if index is not None:
            self.processors.insert(index, processor)
        else:
            self.processors.append(processor)
        logger.info(f"Added processor: {processor.name}")

    def remove_processor(self, name: str) -> bool:
        """Remove a processor by name"""
        for i, p in enumerate(self.processors):
            if p.name == name:
                self.processors.pop(i)
                logger.info(f"Removed processor: {name}")
                return True
        return False

    def submit_event(self, event: SecurityEvent) -> str:
        """Submit an event for processing"""
        # Wrap in EnrichedEvent
        enriched = EnrichedEvent(original_event=event)
        enriched.processing_stages.append(PipelineStage.INGESTION.value)

        # Add to queue with priority
        self._event_queue.put((event.priority.value, enriched))

        return event.id

    def process_event(self, event: EnrichedEvent) -> EnrichedEvent:
        """Process a single event through all processors"""
        try:
            for processor in self.processors:
                if processor.enabled:
                    event = processor.process(event)

            with self._lock:
                self._processed_count += 1

            # Publish processed event
            self._publish_event(event)

            return event

        except Exception as e:
            with self._lock:
                self._error_count += 1
            logger.error(f"Pipeline processing error: {e}")
            raise

    def _publish_event(self, event: EnrichedEvent) -> None:
        """Publish processed event to event bus"""
        try:
            from .v5_orchestrator import get_orchestrator
            orchestrator = get_orchestrator()
            orchestrator.event_bus.publish(
                "event.processed",
                event.to_dict(),
                source="event_pipeline"
            )
        except Exception as e:
            logger.warning(f"Could not publish event: {e}")

    def start(self, num_workers: int = 4) -> None:
        """Start pipeline workers"""
        if self._running:
            return

        self._running = True

        for i in range(num_workers):
            t = threading.Thread(target=self._worker_loop, daemon=True)
            t.start()
            self._worker_threads.append(t)

        logger.info(f"Pipeline started with {num_workers} workers")

    def _worker_loop(self) -> None:
        """Worker thread loop"""
        while self._running:
            try:
                # Get event from queue with timeout
                try:
                    priority, event = self._event_queue.get(timeout=1.0)
                except queue.Empty:
                    continue

                # Process event
                self.process_event(event)
                self._event_queue.task_done()

            except Exception as e:
                logger.error(f"Worker error: {e}")

    def stop(self) -> None:
        """Stop pipeline workers"""
        self._running = False
        for t in self._worker_threads:
            t.join(timeout=5.0)
        self._worker_threads.clear()
        logger.info("Pipeline stopped")

    def get_stats(self) -> Dict[str, Any]:
        """Get pipeline statistics"""
        return {
            "running": self._running,
            "queue_size": self._event_queue.qsize(),
            "workers": len(self._worker_threads),
            "processed_total": self._processed_count,
            "errors_total": self._error_count,
            "processors": [p.get_stats() for p in self.processors]
        }


# Singleton instance
_pipeline_instance: Optional[EventPipeline] = None
_pipeline_lock = threading.Lock()


def get_pipeline() -> EventPipeline:
    """Get or create the singleton pipeline instance"""
    global _pipeline_instance
    with _pipeline_lock:
        if _pipeline_instance is None:
            _pipeline_instance = EventPipeline()
        return _pipeline_instance
