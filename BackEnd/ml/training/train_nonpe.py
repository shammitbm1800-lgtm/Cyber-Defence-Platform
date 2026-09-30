from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score

from ml.nonpe_features import FEATURE_NAMES, STRING_FEATURE_NAMES

RANDOM_STATE = 42


def record_to_vector(record: dict) -> np.ndarray:
    general = record.get("general") or {}
    start = list(general.get("start_bytes") or [])[:4]
    start += [0] * (4 - len(start))

    hist = np.asarray(record.get("histogram") or [0] * 256, dtype=np.float32)
    if hist.size != 256:
        hist = np.resize(hist, 256)
    total = float(hist.sum())
    if total > 0:
        hist /= total

    byteentropy = np.asarray(record.get("byteentropy") or [0] * 256, dtype=np.float32)
    if byteentropy.size != 256:
        byteentropy = np.resize(byteentropy, 256)
    total = float(byteentropy.sum())
    if total > 0:
        byteentropy /= total

    strings = record.get("strings") or {}
    printabledist = np.asarray(strings.get("printabledist") or [0] * 96, dtype=np.float32)
    if printabledist.size != 96:
        printabledist = np.resize(printabledist, 96)
    printable_total = float(strings.get("printables", printabledist.sum()) or 0)
    if printable_total > 0:
        printabledist /= printable_total

    string_counts = strings.get("string_counts") or {}
    ordered_counts = np.asarray(
        [float(string_counts.get(name, 0) or 0) for name in STRING_FEATURE_NAMES],
        dtype=np.float32,
    )

    return np.concatenate([
        np.asarray([
            float(general.get("size", 0) or 0),
            float(general.get("entropy", 0) or 0),
            float(general.get("is_pe", 0) or 0),
            *[float(x) for x in start],
        ], dtype=np.float32),
        hist,
        byteentropy,
        np.asarray([
            float(strings.get("numstrings", 0) or 0),
            float(strings.get("avlength", 0) or 0),
            printable_total,
        ], dtype=np.float32),
        printabledist,
        np.asarray([float(strings.get("entropy", 0) or 0)], dtype=np.float32),
        ordered_counts,
    ])


def load_dataset(paths):
    import orjson
    rows = []
    labels = []
    for path in paths:
        with path.open("rb") as handle:
            for line in handle:
                if line.strip():
                    record = orjson.loads(line)
                    rows.append(record_to_vector(record))
                    labels.append(int(record["label"]))
    return np.asarray(rows, dtype=np.float32), np.asarray(labels, dtype=np.int8)


def train(name: str, train_dir: Path, test_dir: Path, model_dir: Path, report_dir: Path):
    print(f"Loading {name} training data...", flush=True)
    X_train, y_train = load_dataset(sorted(train_dir.glob("*.jsonl")))
    if len(y_train) > 40000:
        idx = np.linspace(0, len(y_train) - 1, 40000, dtype=np.int64)
        X_train, y_train = X_train[idx], y_train[idx]
        print(f"Using deterministic 40,000-row training subset: {X_train.shape}", flush=True)
    print(f"Loaded train: {X_train.shape}", flush=True)
    print(f"Loading {name} test data...", flush=True)
    X_test, y_test = load_dataset(sorted(test_dir.glob("*.jsonl")))
    print(f"Loaded test: {X_test.shape}", flush=True)

    model = RandomForestClassifier(
        n_estimators=20,
        max_depth=12,
        min_samples_leaf=2,
        max_features="sqrt",
        class_weight="balanced_subsample",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    print(f"Training {name} Random Forest...", flush=True)
    model.fit(X_train, y_train)
    print("Testing...", flush=True)
    pred = model.predict(X_test)

    metrics = {
        "model": "RandomForestClassifier",
        "dataset": name,
        "train_size": int(len(y_train)),
        "test_size": int(len(y_test)),
        "feature_count": int(X_train.shape[1]),
        "string_feature_count": len(STRING_FEATURE_NAMES),
        "accuracy": float(accuracy_score(y_test, pred)),
        "precision": float(precision_score(y_test, pred, zero_division=0)),
        "recall": float(recall_score(y_test, pred, zero_division=0)),
        "f1": float(f1_score(y_test, pred, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_test, pred).tolist(),
        "classification_report": classification_report(y_test, pred, target_names=["benign", "malicious"], output_dict=True, zero_division=0),
        "label_semantics": {"0": "benign", "1": "malicious"},
        "feature_schema": FEATURE_NAMES,
    }
    model_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_dir / f"{name}_model.joblib", compress=3)
    (model_dir / f"{name}_feature_schema.json").write_text(json.dumps(FEATURE_NAMES, indent=2), encoding="utf-8")
    (model_dir / f"{name}_string_schema.json").write_text(json.dumps(STRING_FEATURE_NAMES, indent=2), encoding="utf-8")
    (report_dir / f"{name}_metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps({k: metrics[k] for k in ["model", "dataset", "train_size", "test_size", "feature_count", "accuracy", "precision", "recall", "f1", "confusion_matrix"]}, indent=2), flush=True)
    return metrics


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset-root", type=Path, required=True)
    parser.add_argument("--model-dir", type=Path, default=Path(__file__).resolve().parents[1] / "models")
    parser.add_argument("--report-dir", type=Path, default=Path(__file__).resolve().parents[1] / "reports")
    args = parser.parse_args()
    root = args.dataset_root
    pdf = train("pdf", root / "pdf_train", root / "pdf_test", args.model_dir, args.report_dir)
    elf = train("elf", root / "elf_train", root / "elf_test", args.model_dir, args.report_dir)
    (args.report_dir / "nonpe_metrics_summary.json").write_text(json.dumps({"pdf": pdf, "elf": elf}, indent=2), encoding="utf-8")

if __name__ == "__main__":
    main()
