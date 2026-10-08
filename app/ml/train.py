"""Training entry point. Refuses to fit a model without validated labels."""

from __future__ import annotations

from app.ml.dataset import inventory, training_is_possible
from app.ml.model import UNAVAILABLE


def train_baseline() -> dict:
    """Would fit a sklearn classifier on data/processed labeled rows.

    Does not write pickle/joblib. Does not invent labels for samples/IKEv*.pcap.
    """
    info = inventory()
    if not training_is_possible():
        return {
            "trained": False,
            "model_available": False,
            "samples_used": 0,
            "message": UNAVAILABLE,
            "dataset": info,
        }
    return {
        "trained": False,
        "model_available": False,
        "message": "Training path is reserved until labeled rows exist.",
        "dataset": info,
    }


if __name__ == "__main__":
    import json

    print(json.dumps(train_baseline(), indent=2))
