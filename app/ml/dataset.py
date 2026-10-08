"""Dataset layout for a future labeled training set.

Does not invent labels. Sample PCAPs in `samples/` are unlabeled.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
DATA_ROOT = ROOT / "data"
# REQUIREMENTS.md §5.3: ≥ 30 labeled captures covering required axes.
MIN_LABELED_CAPTURES = 30

SUBDIRS = ("normal", "attack", "traffic", "processed")


def inventory() -> dict:
    """Describe what is actually on disk. Filenames only — no absolute paths in API."""
    counts = {}
    for name in SUBDIRS:
        folder = DATA_ROOT / name
        if not folder.is_dir():
            counts[name] = 0
            continue
        files = [
            p.name
            for p in folder.iterdir()
            if p.is_file() and p.name not in {".gitkeep", "README.md"}
        ]
        counts[name] = len(files)
    labeled = counts.get("traffic", 0) + counts.get("normal", 0) + counts.get("attack", 0)
    return {
        "labeled_file_count": labeled,
        "sufficient_for_training": False,
        "minimum_captures_required": MIN_LABELED_CAPTURES,
        "subdirectory_file_counts": counts,
        "unlabeled_demo_samples": ["IKEv1.pcap", "IKEv2.pcap"],
        "note": (
            "No validated inner-traffic labels (web/video/voice) are present. "
            "Do not train a classifier on unlabeled samples."
        ),
    }


def load_labeled_rows() -> list[dict]:
    """Future: rows from data/processed/*.csv. Currently always empty."""
    processed = DATA_ROOT / "processed"
    if not processed.is_dir():
        return []
    rows: list[dict] = []
    for csv_path in sorted(processed.glob("*.csv")):
        # Intentionally unused until a documented schema and provenance exist.
        _ = csv_path.name
    return rows


def training_is_possible() -> bool:
    return (
        len(load_labeled_rows()) >= MIN_LABELED_CAPTURES
        and inventory()["sufficient_for_training"]
    )
