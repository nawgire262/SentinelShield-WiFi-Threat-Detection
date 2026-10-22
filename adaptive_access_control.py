"""adaptive_access_control.py – Risk score-based decision framework and adaptive security actions.

Novelty: Uses dynamically assessed multi-level behavioral risk scores to enforce
adaptive access control policies (Step-Up MFA, session throttling, or quarantine).
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

LOGGER = logging.getLogger(__name__)


@dataclass
class AdaptiveSecurityDecision:
    """Represents an enforcement decision based on behavioral risk."""
    session_id: str
    user_id: str
    timestamp: str
    risk_score: float
    risk_level: str       # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    action: str           # 'ALLOW', 'STEP_UP_MFA', 'CHALLENGE_REAUTH', 'TERMINATE_QUARANTINE'
    action_details: str
    reasons: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AdaptiveAccessControlEngine:
    """Enforces dynamic security policies based on behavioral biometrics & over-efficiency scores."""

    DEFAULT_LOG_PATH = Path("behavioral_audit_log.json")

    def __init__(self, log_path: Optional[Path] = None) -> None:
        self.log_path = log_path or self.DEFAULT_LOG_PATH
        self._audit_trail: List[AdaptiveSecurityDecision] = self._load_audit_trail()

    def _load_audit_trail(self) -> List[AdaptiveSecurityDecision]:
        if not self.log_path.exists():
            return []
        try:
            raw = json.loads(self.log_path.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                return [AdaptiveSecurityDecision(**item) for item in raw]
            return []
        except Exception as exc:
            LOGGER.warning("Could not load behavioral audit log: %s", exc)
            return []

    def _persist_audit_trail(self) -> None:
        try:
            serializable = [d.to_dict() for d in self._audit_trail[-200:]]
            self.log_path.write_text(json.dumps(serializable, indent=2), encoding="utf-8")
        except Exception as exc:
            LOGGER.warning("Could not persist behavioral audit log: %s", exc)

    def evaluate_policy(
        self,
        user_id: str,
        session_id: str,
        biometric_risk: float,
        over_efficiency_score: float,
        hybrid_ml_risk: float,
        extra_reasons: Optional[List[str]] = None,
    ) -> AdaptiveSecurityDecision:
        """Derive composite behavioral risk and trigger the appropriate adaptive security action."""
        reasons = list(extra_reasons or [])

        # Weight composite risk: ML Ensemble (40%) + Over-Efficiency (35%) + Biometric Drift (25%)
        composite_risk = (hybrid_ml_risk * 0.40) + (over_efficiency_score * 0.35) + (biometric_risk * 0.25)
        composite_risk = round(min(100.0, max(0.0, composite_risk)), 1)

        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        # Multi-level decision framework
        if composite_risk >= 80.0:
            level = "CRITICAL"
            action = "TERMINATE_QUARANTINE"
            action_details = "Immediate session termination; IP quarantined; security incident logged; high-priority admin alert dispatched."
            reasons.append("Severe behavioral anomaly & automated bot signature exceeded critical policy threshold (>=80%)")
        elif composite_risk >= 55.0:
            level = "HIGH"
            action = "CHALLENGE_REAUTH"
            action_details = "Session throttled; mandatory re-authentication and behavioral CAPTCHA required to continue."
            reasons.append("High behavioral variance & speed deviation detected (55-79% risk)")
        elif composite_risk >= 30.0:
            level = "MEDIUM"
            action = "STEP_UP_MFA"
            action_details = "Adaptive Step-Up Authentication triggered: secondary TOTP/Push confirmation required."
            reasons.append("Moderate typing rhythm divergence from enrolled baseline (30-54% risk)")
        else:
            level = "LOW"
            action = "ALLOW"
            action_details = "Transparent authentication granted; behavioral biometrics verified within nominal parameters."
            reasons.append("Behavioral biometrics and interaction speed match authentic profile (<30% risk)")

        decision = AdaptiveSecurityDecision(
            session_id=session_id,
            user_id=user_id,
            timestamp=now_iso,
            risk_score=composite_risk,
            risk_level=level,
            action=action,
            action_details=action_details,
            reasons=reasons,
        )

        self._audit_trail.append(decision)
        self._persist_audit_trail()
        return decision

    def get_audit_trail(self, limit: int = 50) -> List[Dict[str, Any]]:
        return [d.to_dict() for d in self._audit_trail[-limit:]][::-1]

