import numpy as np
from typing import List, Dict, Any, Tuple
from sklearn.ensemble import IsolationForest
from src.telemetry.features import TelemetryFeatureExtractor
from src.config import settings

class IdentityThreatDetector:
    """
    Unsupervised IsolationForest model trained on baseline benign user activity
    to detect behavioral identity threats (CTL-10).
    """

    def __init__(self, contamination: float = None, random_state: int = 42):
        self.contamination = contamination or settings.ANOMALY_CONTAMINATION_RATE
        self.random_state = random_state
        self.model = IsolationForest(
            n_estimators=150,
            contamination=self.contamination,
            random_state=self.random_state,
            max_samples="auto"
        )
        self.is_fitted = False

    def train_on_baseline(self, benign_sessions: List[List[Dict[str, Any]]]):
        """Trains IsolationForest exclusively on benign session vectors."""
        X = [TelemetryFeatureExtractor.extract_session_features(session) for session in benign_sessions]
        X = np.array(X)
        self.model.fit(X)
        self.is_fitted = True

    def score_session(self, session_events: List[Dict[str, Any]]) -> Tuple[bool, float, Dict[str, float]]:
        """
        Scores a session.
        Returns:
          - is_anomaly (bool): True if detected as threat
          - anomaly_score (float): raw decision function score (lower means more anomalous)
          - feature_dict (dict): engineered feature values
        """
        if not self.is_fitted:
            raise ValueError("Model must be trained before scoring sessions")

        feats = TelemetryFeatureExtractor.extract_session_features(session_events)
        X = np.array([feats])
        pred = self.model.predict(X)[0]  # -1 for anomaly, 1 for normal
        score = float(self.model.decision_function(X)[0])
        is_anomaly = (pred == -1)

        feature_dict = dict(zip(TelemetryFeatureExtractor.FEATURE_NAMES, feats))
        return is_anomaly, score, feature_dict
