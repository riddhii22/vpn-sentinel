# Future labeled datasets (not populated)

This folder is a **placeholder**. Do not treat files here as ground-truth attacks or traffic classes unless a README in that subfolder says so.

| Path | Intended use |
| --- | --- |
| `normal/` | Later: labeled benign captures |
| `attack/` | Later: labeled attack captures (lab only) |
| `traffic/` | Later: web / video / voice labeled runs |
| `processed/` | Later: CSV feature tables + train/test split |

**Current repo:** unlabeled IKE samples plus `samples/esp_weird.pcap` (synthetic metadata outlier). IsolationForest is fitted on the IKE sample ESP flows only. That is **not** enough to train or evaluate a traffic-class Random Forest.

Do **not** copy those samples here with invented labels.
