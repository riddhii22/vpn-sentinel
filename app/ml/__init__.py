"""ML interface. No fake model: we do not have labeled web/video/voice captures."""

from __future__ import annotations

from app.ml.dataset import inventory, training_is_possible
from app.ml.model import UNAVAILABLE, load_trained_model
from app.ml.preprocess import FEATURE_NAMES, features_to_vector

__all__ = [
    "UNAVAILABLE",
    "FEATURE_NAMES",
    "features_to_vector",
    "inventory",
    "predict_from_features",
]


def predict_from_features(features: dict) -> dict:
    """Never invents a class or confidence. sklearn is installed but unused here."""
    if not isinstance(features, dict):
        raise ValueError("features must be a dict of numeric traffic metadata")

    # Validate the vector even when we will not score it, so the pipeline is real.
    try:
        vector = features_to_vector(features)
    except ValueError:
        vector = None

    available = bool(load_trained_model()) and training_is_possible()
    if available:
        # Unreachable until a validated training set and loader exist.
        raise RuntimeError("trained model path is not implemented")

    return {
        "features": features,
        "prediction": None,
        "confidence": None,
        "model_available": False,
        "message": UNAVAILABLE,
        "model_type": None,
        "feature_names": list(FEATURE_NAMES),
        "feature_vector": vector,
        "feature_importance": None,
        "dataset": inventory(),
        "explains": (
            "The AI does not read encrypted content. It would use observable "
            "traffic characteristics such as packet size and timing. "
            "No validated training set exists in this repository yet, so there "
            "is no prediction and no confidence."
        ),
    }
