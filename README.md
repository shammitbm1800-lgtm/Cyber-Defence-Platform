# Cyber Defence Platform

**Phase 2 complete build:** local ML detection for URL, Email, SMS, Ransomware and Malicious PE files, plus the new Malicious File Analyzer.

See [`PHASE2_IMPLEMENTATION.md`](PHASE2_IMPLEMENTATION.md) for model results, architecture, changed files and run instructions.

A unified cybersecurity platform for detecting:

- Phishing URLs
- Phishing Emails
- SMS Spam / Smishing
- Ransomware / Malware

## Technology Stack

- Python
- Flask
- HTML
- CSS
- JavaScript
- SQLite
- REST APIs
- Tesseract OCR

## Project Structure

```text
Makings/
├── BackEnd/
├── FrontEnd/
├── .env.example
└── .gitignore

## Phase 2 — ML Threat Detection

Phase 2 adds local machine-learning classifiers without removing the existing API-based detection modules.

### ML modules

- URL phishing classifier: Random Forest using reproducible lexical URL features.
- Email phishing classifier: TF-IDF + Logistic Regression on email text.
- SMS spam/smishing classifier: TF-IDF + Logistic Regression on SMS text.
- Ransomware classifier: Random Forest on the first 1024 bytes of Windows PE files.
- Malicious file classifier: Random Forest on static PE header/section/import/directory features.

OCR remains the text-extraction layer. OCR URL/email/SMS flows reuse the corresponding ML classifiers after text extraction.

### Malicious File Analyzer

The new File Analyzer accepts Windows PE files (`.exe`, `.dll`, `.sys`, `.scr`, `.cpl`, `.ocx`, `.efi`, `.com`). Uploaded files are treated as untrusted and are never executed. The analyzer calculates SHA-256, parses the PE statically, extracts suspicious characteristics, runs the trained malware model, stores the result in the existing `Scan` history model, and supports optional application-level quarantine.

### Training

The trained model artifacts are included under `BackEnd/ml/models/`. To retrain from the public datasets, see `BackEnd/ml/datasets_README.md` and run:

```powershell
cd BackEnd
python -m ml.training.train_all --data-root "C:\path\to\datasets"
```

The current evaluation reports are in `BackEnd/ml/reports/`.

### Running

The Phase 2 build now serves the existing FrontEnd directly from Flask. **You do not need Live Server or a second frontend server.**

Install dependencies:

```powershell
cd BackEnd
python -m pip install -r requirements.txt
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

Keep the Flask terminal running while using the platform. The frontend assets (HTML, CSS, JavaScript and images) are served by the same Flask process.

### Security note

This is a static ML-based detection component, not a replacement for commercial antivirus/EDR. Model metrics are holdout measurements on the supplied datasets and do not guarantee detection of future or previously unseen threats.
