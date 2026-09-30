# Malicious File Analyzer ML Scope

The analyzer preserves the existing PE malware model and adds locally trained PDF and ELF classifiers.

## Models

- `malicious_file_model.joblib` — existing PE model, preserved.
- `pdf_model.joblib` — Random Forest trained from the supplied EMBER2024 PDF train split and evaluated on the supplied PDF test split.
- `elf_model.joblib` — Random Forest trained from the supplied EMBER2024 ELF train split and evaluated on the supplied ELF test split.

The PDF and ELF models use 696 static features from the supplied EMBER2024 records: general file information, byte histogram, byte/entropy histogram, and string statistics/IOC counts. Uploaded files are never executed.

## Training note

The supplied train sets are large. To keep training reproducible and practical on a student development machine, the committed models were trained on a deterministic 40,000-row subset of each train split and evaluated against the complete supplied test split.

## Results

See `reports/pdf_metrics.json` and `reports/elf_metrics.json` for precision, recall, F1 and confusion matrices.
