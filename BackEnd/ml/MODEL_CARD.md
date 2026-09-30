# Phase 2 ML Model Card

All metrics below are from stratified 80/20 holdout tests using random seed 42 on the datasets supplied for this build. No execution of malware or ransomware binaries was used for training or testing.

| Model | Algorithm | Rows used | Accuracy | Precision | Recall | F1 |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| URL | Random Forest | 11,000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| Email | TF-IDF + Logistic Regression | 82,077 | 0.9910 | 0.9894 | 0.9935 | 0.9914 |
| SMS | TF-IDF + Logistic Regression | 5,169 | 0.9778 | 0.9091 | 0.9160 | 0.9125 |
| Ransomware | Random Forest | 2,157 | 0.9792 | 0.9667 | 0.9902 | 0.9783 |
| Malicious File | Random Forest | 19,611 | 0.9903 | 0.9888 | 0.9983 | 0.9935 |

## Interpretation

These are dataset-specific holdout measurements, not guarantees of production detection quality. In particular, extremely high scores on engineered cybersecurity datasets can reflect dataset characteristics and do not establish that the model will generalize to every real-world threat.

## Artifacts

- `url_model.joblib`
- `email_model.joblib`
- `sms_model.joblib`
- `ransomware_model.joblib`
- `malicious_file_model.joblib`
- feature-schema JSON files
- per-model metric JSON files
- confusion-matrix/feature-importance PNG files
