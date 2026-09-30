# Phase 2 ML Training Data

The trained `.joblib` model files are included in `models/` for immediate application inference.

The raw datasets are intentionally not copied into the final application ZIP because some are large. To retrain, place these source files under a local data directory and pass the directory to the training script:

- URL: Binary-Dataset-of-Phishing-and-Legitimate-URLs_dataset (ARFF)
- Email: phishing_email_dataset_ (ARFF-like file with `text_combined`, `label`)
- SMS: SMSSpamCollection (tab-separated text)
- Ransomware: Ransomware_headers.csv
- Malicious file: dataset_malwares.csv

The current trained artifacts were produced from the datasets supplied for this project. The training code performs cleaning, duplicate removal for text datasets, stratified 80/20 splits, fixed random seed 42, training, and evaluation.

Do not execute any malware or ransomware binaries during training or testing.
