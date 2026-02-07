"""
Shannon AI Pentester Manager
============================
Python wrapper for Shannon CLI execution and session management.
Handles async pentest execution, monitoring, and result collection.
"""

import subprocess
import json
import asyncio
import os
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class ShannonStatus(Enum):
    """Shannon session status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ShannonSession:
    """Shannon pentest session"""
    session_id: str
    target_url: str
    repo_path: Optional[str]
    status: ShannonStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    metrics: Optional[Dict] = None
    findings: List = field(default_factory=list)
    raw_output: str = ""
    error_message: str = ""
    config: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'session_id': self.session_id,
            'target_url': self.target_url,
            'repo_path': self.repo_path,
            'status': self.status.value,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'metrics': self.metrics,
            'findings_count': len(self.findings),
            'has_critical': any(f.severity.value == 'critical' for f in self.findings) if self.findings else False,
            'error_message': self.error_message
        }


class ShannonManager:
    """Shannon AI Pentester manager - orchestrates pentest sessions"""

    SHANNON_PATH = Path("/home/lydian/Desktop/TSUNAMI/modules/shannon")
    OUTPUT_PATH = Path("/home/lydian/Desktop/TSUNAMI/data/shannon_results")

    # Temporal server settings
    TEMPORAL_ADDRESS = os.getenv("TEMPORAL_ADDRESS", "localhost:7233")

    def __init__(self):
        self._active_sessions: Dict[str, ShannonSession] = {}
        self._completed_sessions: Dict[str, ShannonSession] = {}
        self._ensure_paths()
        self._shannon_available = self._check_shannon()
        logger.info(f"[SHANNON] Manager initialized. Available: {self._shannon_available}")

    def _ensure_paths(self):
        """Ensure output directories exist"""
        self.OUTPUT_PATH.mkdir(parents=True, exist_ok=True)

    def _check_shannon(self) -> bool:
        """Check if Shannon is available"""
        # Check for npx availability (Shannon uses npx)
        try:
            result = subprocess.run(
                ["which", "npx"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def is_available(self) -> bool:
        """Check if Shannon is available for use"""
        return self._shannon_available and self.SHANNON_PATH.exists()

    async def start_pentest(
        self,
        target_url: str,
        repo_path: Optional[str] = None,
        config: Optional[Dict] = None,
        auth_config: Optional[Dict] = None
    ) -> str:
        """
        Start a new pentest session

        Args:
            target_url: Target application URL
            repo_path: Optional source code repository path (white-box testing)
            config: Optional Shannon configuration
            auth_config: Optional authentication configuration

        Returns:
            session_id: Unique session identifier
        """
        session_id = f"shannon_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{os.urandom(4).hex()}"
        output_dir = self.OUTPUT_PATH / session_id
        output_dir.mkdir(parents=True, exist_ok=True)

        # Create session
        session = ShannonSession(
            session_id=session_id,
            target_url=target_url,
            repo_path=repo_path,
            status=ShannonStatus.PENDING,
            start_time=datetime.now(),
            config=config or {}
        )

        # Save auth config if provided
        if auth_config:
            auth_file = output_dir / "auth-config.json"
            auth_file.write_text(json.dumps(auth_config, indent=2))
            session.config['auth_config'] = str(auth_file)

        self._active_sessions[session_id] = session

        # Start async execution
        asyncio.create_task(self._execute_pentest(session_id))

        logger.info(f"[SHANNON] Pentest started: {session_id} -> {target_url}")
        return session_id

    async def _execute_pentest(self, session_id: str):
        """Execute Shannon pentest asynchronously"""
        session = self._active_sessions.get(session_id)
        if not session:
            return

        session.status = ShannonStatus.RUNNING
        output_dir = self.OUTPUT_PATH / session_id

        try:
            # Build Shannon command
            # Shannon uses: npx @anthropic-ai/claude-code start URL=<url> [REPO=<path>]
            cmd = [
                "npx",
                "@anthropic-ai/claude-code",
                "start",
                f"URL={session.target_url}"
            ]

            if session.repo_path:
                cmd.append(f"REPO={session.repo_path}")

            # Add config file if exists
            if 'auth_config' in session.config:
                cmd.append(f"CONFIG={session.config['auth_config']}")

            # Add output directory
            cmd.append(f"OUTPUT={output_dir}")

            logger.info(f"[SHANNON] Executing: {' '.join(cmd)}")

            # Execute with timeout (pentests can take 30+ minutes)
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(self.SHANNON_PATH)
            )

            # Wait with timeout (60 minutes max)
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=3600
                )
                session.raw_output = stdout.decode() if stdout else ""

                if process.returncode == 0:
                    session.status = ShannonStatus.COMPLETED
                    await self._parse_results(session_id)
                else:
                    session.status = ShannonStatus.FAILED
                    session.error_message = stderr.decode() if stderr else "Unknown error"

            except asyncio.TimeoutError:
                process.kill()
                session.status = ShannonStatus.FAILED
                session.error_message = "Pentest timed out after 60 minutes"

        except Exception as e:
            session.status = ShannonStatus.FAILED
            session.error_message = str(e)
            logger.error(f"[SHANNON] Execution error: {e}")

        finally:
            session.end_time = datetime.now()
            # Move to completed
            self._completed_sessions[session_id] = session
            if session_id in self._active_sessions:
                del self._active_sessions[session_id]

            logger.info(f"[SHANNON] Pentest finished: {session_id} - {session.status.value}")

    async def _parse_results(self, session_id: str):
        """Parse Shannon output files"""
        session = self._active_sessions.get(session_id) or self._completed_sessions.get(session_id)
        if not session:
            return

        output_dir = self.OUTPUT_PATH / session_id

        # Parse session.json
        session_file = output_dir / "session.json"
        if session_file.exists():
            try:
                session.metrics = json.loads(session_file.read_text())
            except Exception as e:
                logger.warning(f"[SHANNON] Failed to parse session.json: {e}")

        # Parse markdown report
        report_file = output_dir / "deliverables" / "shannon-report.md"
        if not report_file.exists():
            # Try alternative locations
            for alt_path in [
                output_dir / "report.md",
                output_dir / "shannon-report.md"
            ]:
                if alt_path.exists():
                    report_file = alt_path
                    break

        if report_file.exists():
            try:
                from .result_parser import parse_shannon_report
                session.findings = parse_shannon_report(report_file.read_text())
                logger.info(f"[SHANNON] Parsed {len(session.findings)} findings from report")
            except Exception as e:
                logger.warning(f"[SHANNON] Failed to parse report: {e}")

    def get_session(self, session_id: str) -> Optional[ShannonSession]:
        """Get session by ID"""
        return self._active_sessions.get(session_id) or self._completed_sessions.get(session_id)

    def get_session_status(self, session_id: str) -> Optional[Dict]:
        """Get session status as dictionary"""
        session = self.get_session(session_id)
        if not session:
            return None
        return session.to_dict()

    def list_sessions(self, include_completed: bool = True) -> List[Dict]:
        """List all sessions"""
        sessions = []

        # Active sessions
        for session in self._active_sessions.values():
            sessions.append(session.to_dict())

        # Completed sessions
        if include_completed:
            for session in self._completed_sessions.values():
                sessions.append(session.to_dict())

        return sorted(sessions, key=lambda x: x['start_time'], reverse=True)

    def get_findings(self, session_id: str) -> List:
        """Get findings for a session"""
        session = self.get_session(session_id)
        if not session:
            return []
        return session.findings

    async def cancel_pentest(self, session_id: str) -> bool:
        """Cancel a running pentest"""
        session = self._active_sessions.get(session_id)
        if not session or session.status != ShannonStatus.RUNNING:
            return False

        session.status = ShannonStatus.CANCELLED
        session.end_time = datetime.now()
        session.error_message = "Cancelled by user"

        # Move to completed
        self._completed_sessions[session_id] = session
        del self._active_sessions[session_id]

        logger.info(f"[SHANNON] Pentest cancelled: {session_id}")
        return True

    def get_statistics(self) -> Dict:
        """Get overall statistics"""
        all_sessions = list(self._active_sessions.values()) + list(self._completed_sessions.values())

        total_findings = sum(len(s.findings) for s in all_sessions)
        critical_findings = sum(
            1 for s in all_sessions
            for f in s.findings
            if f.severity.value == 'critical'
        )
        high_findings = sum(
            1 for s in all_sessions
            for f in s.findings
            if f.severity.value == 'high'
        )

        return {
            'total_sessions': len(all_sessions),
            'active_sessions': len(self._active_sessions),
            'completed_sessions': len([s for s in all_sessions if s.status == ShannonStatus.COMPLETED]),
            'failed_sessions': len([s for s in all_sessions if s.status == ShannonStatus.FAILED]),
            'total_findings': total_findings,
            'critical_findings': critical_findings,
            'high_findings': high_findings,
            'success_rate': (
                len([s for s in all_sessions if s.status == ShannonStatus.COMPLETED]) /
                len(all_sessions) * 100 if all_sessions else 0
            )
        }
