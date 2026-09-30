"""
Reproducible training pipeline for Cyber Defence Platform Phase 2.

Usage example (Windows PowerShell):
    python -m ml.training.train_all --data-root "C:\\path\\to\\datasets"

Expected files:
    <data-root>/url/Binary-Dataset-of-Phishing-and-Legitimate-URLs_dataset
    <data-root>/email/phishing_email_dataset_
    <data-root>/sms/SMSSpamCollection
    <data-root>/ransomware/Ransomware_headers.csv
    <data-root>/malicious/dataset_malwares.csv
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from scipy.io import arff
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    f1_score, precision_score, recall_score
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

RANDOM_STATE = 42
URL_FEATURES = [
    "dot_count","url_len","digit_count","special_count","hyphen_count",
    "double_slash","single_slash","at_the_rate","protocol","protocol_count"
]
PE_FEATURES = [
    "e_magic","e_cblp","e_cp","e_crlc","e_cparhdr","e_minalloc","e_maxalloc","e_ss","e_sp",
    "e_csum","e_ip","e_cs","e_lfarlc","e_ovno","e_oemid","e_oeminfo","e_lfanew","Machine",
    "NumberOfSections","TimeDateStamp","PointerToSymbolTable","NumberOfSymbols",
    "SizeOfOptionalHeader","Characteristics","Magic","MajorLinkerVersion","MinorLinkerVersion",
    "SizeOfCode","SizeOfInitializedData","SizeOfUninitializedData","AddressOfEntryPoint","BaseOfCode",
    "ImageBase","SectionAlignment","FileAlignment","MajorOperatingSystemVersion",
    "MinorOperatingSystemVersion","MajorImageVersion","MinorImageVersion","MajorSubsystemVersion",
    "MinorSubsystemVersion","SizeOfHeaders","CheckSum","SizeOfImage","Subsystem","DllCharacteristics",
    "SizeOfStackReserve","SizeOfStackCommit","SizeOfHeapReserve","SizeOfHeapCommit","LoaderFlags",
    "NumberOfRvaAndSizes","SuspiciousImportFunctions","SuspiciousNameSection","SectionsLength",
    "SectionMinEntropy","SectionMaxEntropy","SectionMinRawsize","SectionMaxRawsize",
    "SectionMinVirtualsize","SectionMaxVirtualsize","SectionMaxPointerData","SectionMinPointerData",
    "SectionMaxChar","SectionMainChar","DirectoryEntryImport","DirectoryEntryImportSize",
    "DirectoryEntryExport","ImageDirectoryEntryExport","ImageDirectoryEntryImport",
    "ImageDirectoryEntryResource","ImageDirectoryEntryException","ImageDirectoryEntrySecurity"
]

def metrics(y_true, y_pred, names):
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
        "classification_report": classification_report(
            y_true, y_pred, target_names=names, output_dict=True, zero_division=0
        )
    }

def parse_text_arff(path: Path):
    texts, labels = [], []
    in_data = False
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            line = raw.strip()
            if not in_data:
                if line.upper() == "@DATA":
                    in_data = True
                continue
            if not line:
                continue
            text_part, label_part = line.rsplit(",", 1)
            text_part = text_part.strip()
            if text_part.startswith("'") and text_part.endswith("'"):
                text_part = text_part[1:-1]
            text_part = text_part.replace("\\'", "'").replace("''", "'")
            texts.append(text_part)
            labels.append(int(label_part.strip()))
    return texts, labels

def parse_url_arff(path: Path):
    data, _ = arff.loadarff(path)
    frame = pd.DataFrame(data)
    for col in frame.columns:
        if frame[col].dtype == object:
            frame[col] = frame[col].map(
                lambda x: x.decode() if isinstance(x, (bytes, bytearray)) else x
            )
    return frame.dropna()

def train_url(path: Path, model_dir: Path, report_dir: Path):
    df = parse_url_arff(path)
    X, y = df[URL_FEATURES].astype(np.float32), df["label"].astype(int)
    Xtr, Xte, ytr, yte = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=RANDOM_STATE
    )
    model = RandomForestClassifier(
        n_estimators=350, random_state=RANDOM_STATE, n_jobs=-1,
        class_weight="balanced_subsample", max_features="sqrt"
    )
    model.fit(Xtr, ytr)
    pred = model.predict(Xte)
    result = metrics(yte, pred, ["phishing", "legitimate"])
    result.update({
        "model": "RandomForestClassifier",
        "dataset_rows": int(len(df)), "train_size": int(len(Xtr)),
        "test_size": int(len(Xte)), "features": URL_FEATURES,
        "label_semantics": {"0": "phishing", "1": "legitimate"}
    })
    joblib.dump(model, model_dir / "url_model.joblib", compress=3)
    (model_dir / "url_feature_schema.json").write_text(json.dumps(URL_FEATURES, indent=2))
    (report_dir / "url_metrics.json").write_text(json.dumps(result, indent=2))
    return result

def train_email(path: Path, model_dir: Path, report_dir: Path):
    texts, labels = parse_text_arff(path)
    df = pd.DataFrame({"text": texts, "label": labels})
    df["normalized"] = (
        df["text"].str.lower().str.replace(r"\s+", " ", regex=True).str.strip()
    )
    df = df[df["normalized"].str.len() > 0].drop_duplicates("normalized").drop(columns="normalized")
    Xtr, Xte, ytr, yte = train_test_split(
        df["text"], df["label"], test_size=0.20, stratify=df["label"], random_state=RANDOM_STATE
    )
    model = Pipeline([
        ("tfidf", TfidfVectorizer(
            lowercase=True, strip_accents="unicode", ngram_range=(1,2),
            min_df=2, max_df=0.995, max_features=80000,
            sublinear_tf=True, token_pattern=r"(?u)\b[\w$][\w$'./:-]*\b"
        )),
        ("clf", LogisticRegression(
            solver="liblinear", max_iter=500, C=4.0,
            class_weight="balanced", random_state=RANDOM_STATE
        ))
    ])
    model.fit(Xtr, ytr)
    pred = model.predict(Xte)
    result = metrics(yte, pred, ["legitimate", "phishing"])
    result.update({
        "model": "TfidfVectorizer+LogisticRegression",
        "dataset_rows": int(len(df)), "train_size": int(len(Xtr)),
        "test_size": int(len(Xte)), "duplicates_removed": int(len(texts)-len(df)),
        "label_semantics": {"0": "legitimate", "1": "phishing"}
    })
    joblib.dump(model, model_dir / "email_model.joblib", compress=3)
    (report_dir / "email_metrics.json").write_text(json.dumps(result, indent=2))
    return result

def train_sms(path: Path, model_dir: Path, report_dir: Path):
    df = pd.read_csv(path, sep="\t", header=None, names=["label", "text"], encoding="utf-8").dropna()
    df["y"] = (df["label"].str.lower() == "spam").astype(int)
    df = df.drop_duplicates("text")
    Xtr, Xte, ytr, yte = train_test_split(
        df["text"], df["y"], test_size=0.20, stratify=df["y"], random_state=RANDOM_STATE
    )
    model = Pipeline([
        ("tfidf", TfidfVectorizer(lowercase=True, strip_accents="unicode",
                                  ngram_range=(1,2), min_df=1, max_features=25000,
                                  sublinear_tf=True)),
        ("clf", LogisticRegression(
            solver="liblinear", max_iter=300, C=4.0,
            class_weight="balanced", random_state=RANDOM_STATE
        ))
    ])
    model.fit(Xtr, ytr)
    pred = model.predict(Xte)
    result = metrics(yte, pred, ["ham", "spam"])
    result.update({
        "model": "TfidfVectorizer+LogisticRegression",
        "dataset_rows": int(len(df)), "train_size": int(len(Xtr)),
        "test_size": int(len(Xte)), "label_semantics": {"0": "ham", "1": "spam"}
    })
    joblib.dump(model, model_dir / "sms_model.joblib", compress=3)
    (report_dir / "sms_metrics.json").write_text(json.dumps(result, indent=2))
    return result

def train_ransomware(path: Path, model_dir: Path, report_dir: Path):
    df = pd.read_csv(path)
    features = [str(i) for i in range(1024)]
    X, y = df[features].astype(np.float32), df["GR"].astype(int)
    Xtr, Xte, ytr, yte = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=RANDOM_STATE
    )
    model = RandomForestClassifier(
        n_estimators=400, random_state=RANDOM_STATE, n_jobs=-1,
        class_weight="balanced_subsample", max_features="sqrt"
    )
    model.fit(Xtr, ytr)
    pred = model.predict(Xte)
    result = metrics(yte, pred, ["goodware", "ransomware"])
    result.update({
        "model": "RandomForestClassifier", "dataset_rows": int(len(df)),
        "train_size": int(len(Xtr)), "test_size": int(len(Xte)),
        "feature_count": len(features), "label_semantics": {"0":"goodware","1":"ransomware"}
    })
    joblib.dump(model, model_dir / "ransomware_model.joblib", compress=3)
    (model_dir / "ransomware_feature_schema.json").write_text(json.dumps(features, indent=2))
    (report_dir / "ransomware_metrics.json").write_text(json.dumps(result, indent=2))
    return result

def train_malicious_file(path: Path, model_dir: Path, report_dir: Path):
    df = pd.read_csv(path)
    X, y = df[PE_FEATURES].astype(np.float32), df["Malware"].astype(int)
    Xtr, Xte, ytr, yte = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=RANDOM_STATE
    )
    model = RandomForestClassifier(
        n_estimators=400, random_state=RANDOM_STATE, n_jobs=-1,
        class_weight="balanced_subsample", max_features="sqrt"
    )
    model.fit(Xtr, ytr)
    pred = model.predict(Xte)
    result = metrics(yte, pred, ["benign", "malicious"])
    result.update({
        "model": "RandomForestClassifier", "dataset_rows": int(len(df)),
        "train_size": int(len(Xtr)), "test_size": int(len(Xte)),
        "feature_count": len(PE_FEATURES), "label_semantics": {"0":"benign","1":"malicious"}
    })
    joblib.dump(model, model_dir / "malicious_file_model.joblib", compress=3)
    (model_dir / "malicious_file_feature_schema.json").write_text(json.dumps(PE_FEATURES, indent=2))
    (report_dir / "malicious_file_metrics.json").write_text(json.dumps(result, indent=2))
    return result

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-root", type=Path, required=True)
    args = parser.parse_args()
    root = args.data_root
    model_dir = Path(__file__).resolve().parents[1] / "models"
    report_dir = Path(__file__).resolve().parents[1] / "reports"
    model_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    results = {
        "url": train_url(root/"url"/"Binary-Dataset-of-Phishing-and-Legitimate-URLs_dataset", model_dir, report_dir),
        "email": train_email(root/"email"/"phishing_email_dataset_", model_dir, report_dir),
        "sms": train_sms(root/"sms"/"SMSSpamCollection", model_dir, report_dir),
        "ransomware": train_ransomware(root/"ransomware"/"Ransomware_headers.csv", model_dir, report_dir),
        "malicious_file": train_malicious_file(root/"malicious"/"dataset_malwares.csv", model_dir, report_dir),
    }
    (report_dir/"model_metrics_summary.json").write_text(json.dumps(results, indent=2))
    print(json.dumps({k:{m:v for m,v in val.items() if m in ("model","accuracy","precision","recall","f1","confusion_matrix")}
                      for k,val in results.items()}, indent=2))

if __name__ == "__main__":
    main()
