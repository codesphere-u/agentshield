"""Tamper-evident SHA-256 hash-chained audit ledger for AI agent governance."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agentshield.models import AuditEntry, EvaluationVerdict, PolicyDecision, RiskLevel

GENESIS_HASH = "0" * 64


class AuditLedger:
    """Append-only SHA-256 hash-chained audit log that detects any historical mutation or deletion."""

    def __init__(self, persist_path: str | Path | None = None) -> None:
        self._entries: list[AuditEntry] = []
        self.persist_path = Path(persist_path) if persist_path else None
        if self.persist_path and self.persist_path.exists():
            self._load()

    @property
    def entries(self) -> list[AuditEntry]:
        return list(self._entries)

    @staticmethod
    def _compute_entry_hash(
        *,
        sequence_id: int,
        entry_id: str,
        timestamp: str,
        event_type: str,
        actor: str,
        subject: str,
        decision: PolicyDecision,
        risk_level: RiskLevel,
        finding_count: int,
        summary: str,
        previous_hash: str,
    ) -> str:
        payload = {
            "sequence_id": sequence_id,
            "entry_id": entry_id,
            "timestamp": timestamp,
            "event_type": event_type,
            "actor": actor,
            "subject": subject,
            "decision": decision.value,
            "risk_level": risk_level.value,
            "finding_count": finding_count,
            "summary": summary,
            "previous_hash": previous_hash,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def record(
        self,
        *,
        event_type: str,
        subject: str,
        verdict: EvaluationVerdict,
        actor: str = "default-agent",
        summary: str | None = None,
    ) -> AuditEntry:
        """Append a new cryptographically chained entry for an evaluation verdict."""
        sequence_id = len(self._entries) + 1
        previous_hash = self._entries[-1].entry_hash if self._entries else GENESIS_HASH
        timestamp = datetime.now(timezone.utc).isoformat()
        entry_id = f"aud_{sequence_id:06d}_{verdict.verdict_id[-6:]}"
        computed_summary = (
            summary
            if summary is not None
            else (
                "; ".join(f.title for f in verdict.findings)
                if verdict.findings
                else "Clean evaluation (no findings)"
            )
        )

        entry_hash = self._compute_entry_hash(
            sequence_id=sequence_id,
            entry_id=entry_id,
            timestamp=timestamp,
            event_type=event_type,
            actor=actor,
            subject=subject,
            decision=verdict.decision,
            risk_level=verdict.risk_level,
            finding_count=len(verdict.findings),
            summary=computed_summary,
            previous_hash=previous_hash,
        )

        entry = AuditEntry(
            sequence_id=sequence_id,
            entry_id=entry_id,
            timestamp=timestamp,
            event_type=event_type,
            actor=actor,
            subject=subject,
            decision=verdict.decision,
            risk_level=verdict.risk_level,
            finding_count=len(verdict.findings),
            summary=computed_summary,
            previous_hash=previous_hash,
            entry_hash=entry_hash,
        )
        self._entries.append(entry)
        if self.persist_path:
            self._append_to_disk(entry)
        return entry

    def verify_integrity(self) -> tuple[bool, str]:
        """Verify the cryptographic hash chain across all entries."""
        expected_prev = GENESIS_HASH
        for idx, entry in enumerate(self._entries, start=1):
            if entry.sequence_id != idx:
                return (
                    False,
                    f"Sequence gap or reordering at index {idx}: expected sequence_id={idx}, got {entry.sequence_id}",
                )
            if entry.previous_hash != expected_prev:
                return (
                    False,
                    f"Broken previous_hash link at sequence_id={entry.sequence_id}",
                )
            recomputed = self._compute_entry_hash(
                sequence_id=entry.sequence_id,
                entry_id=entry.entry_id,
                timestamp=entry.timestamp,
                event_type=entry.event_type,
                actor=entry.actor,
                subject=entry.subject,
                decision=entry.decision,
                risk_level=entry.risk_level,
                finding_count=entry.finding_count,
                summary=entry.summary,
                previous_hash=entry.previous_hash,
            )
            if entry.entry_hash != recomputed:
                return (
                    False,
                    f"Hash mismatch at sequence_id={entry.sequence_id} (entry_id={entry.entry_id})",
                )
            expected_prev = entry.entry_hash

        return (
            True,
            f"Verified {len(self._entries)} chained audit entries. Head hash: {expected_prev[:16]}...",
        )

    def to_dict_list(self) -> list[dict[str, Any]]:
        return [e.model_dump(mode="json") for e in self._entries]

    def _append_to_disk(self, entry: AuditEntry) -> None:
        if not self.persist_path:
            return
        self.persist_path.parent.mkdir(parents=True, exist_ok=True)
        with self.persist_path.open("a", encoding="utf-8") as fh:
            fh.write(entry.model_dump_json() + "\n")

    def _load(self) -> None:
        if not self.persist_path or not self.persist_path.exists():
            return
        self._entries.clear()
        with self.persist_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped:
                    self._entries.append(AuditEntry.model_validate_json(stripped))
