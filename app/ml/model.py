"""Model interface. Does not load pickle/joblib from the dataset tree."""

from __future__ import annotations

UNAVAILABLE = "AI prediction unavailable — insufficient validated training data."


class ModelUnavailableError(ValueError):
    """Raised when a caller demands a prediction that cannot be produced."""


def load_trained_model():
    """Return a fitted estimator, or None.

    This phase does **not** call pickle or joblib.load. Files under data/ are
    untrusted; a pickled object could execute code. sklearn is installed for a
    future training script, not used here.
    """
    return None


def model_available() -> bool:
    return load_trained_model() is not None


def predict_vector(_vector: list[float]) -> dict:
    """Would classify inner traffic (web/video/voice) if a validated model existed."""
    if not model_available():
        return {
            "prediction": None,
            "confidence": None,
            "feature_importance": None,
        }
    raise ModelUnavailableError(UNAVAILABLE)
