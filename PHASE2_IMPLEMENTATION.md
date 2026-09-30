# Cyber Defence Platform — Phase 2 Implementation

## Scope

This build extends the existing Cyber Defence Platform without replacing its working detection modules.

Phase 2 adds local ML detection for:
- URL phishing
- Email phishing
- SMS spam/smishing
- Ransomware
- Malicious PE files

OCR remains an extraction layer. OCR URL/email/SMS flows reuse the corresponding local ML detector after text extraction.

## ML models included

| Module | Model | Training rows | Accuracy | Precision | Recall | F1 |
|---|---|---:|---:|---:|---:|---:|
| URL | Random Forest | 11,000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| Email | TF-IDF + Logistic Regression | 82,077 | 0.9910 | 0.9894 | 0.9935 | 0.9914 |
| SMS | TF-IDF + Logistic Regression | 5,169 | 0.9778 | 0.9091 | 0.9160 | 0.9125 |
| Ransomware | Random Forest | 2,157 | 0.9792 | 0.9667 | 0.9902 | 0.9783 |
| Malicious File | Random Forest | 19,611 | 0.9903 | 0.9888 | 0.9983 | 0.9935 |

All reported metrics are stratified 80/20 holdout measurements using random seed 42 on the supplied datasets. They are dataset-specific measurements and are not guarantees of real-world detection performance.

## Main files added

### ML
- `BackEnd/ml/model_registry.py`
- `BackEnd/ml/predictors.py`
- `BackEnd/ml/url_features.py`
- `BackEnd/ml/ransomware_features.py`
- `BackEnd/ml/pe_features.py`
- `BackEnd/ml/training/train_all.py`
- `BackEnd/ml/training/test_inference.py`
- `BackEnd/ml/models/*`
- `BackEnd/ml/reports/*`

### File analyzer
- `BackEnd/services/file_analysis_service.py`
- `BackEnd/services/quarantine_service.py`
- `BackEnd/controllers/file_controller.py`
- `BackEnd/routes/file_routes.py`

### ML integration
- `BackEnd/services/ml_detection_service.py`
- Additive modifications to the existing URL, Email, SMS and Ransomware services/controllers.

### Frontend
- Existing `FrontEnd/index.html` and `FrontEnd/js/app.js` extended with the File Analyzer interface and ML result display.

## Malicious File Analyzer

Supported uploaded PE file extensions:
`.exe`, `.dll`, `.sys`, `.scr`, `.cpl`, `.ocx`, `.efi`, `.com`

The analyzer:
1. validates the upload
2. calculates SHA-256
3. parses PE structures without executing the file
4. extracts the trained model's 73 static PE features
5. runs the saved Random Forest
6. displays benign/suspicious/malicious classification and probability
7. shows selected static suspicious indicators
8. stores the result in the existing `Scan` table
9. can optionally quarantine the uploaded artifact in the application's controlled quarantine directory

Uploaded files are never executed by the analyzer.

## Training

The final runtime project contains the trained model artifacts. Raw datasets are not copied into the runtime project.

To retrain, arrange the supplied datasets as described in:
`BackEnd/ml/datasets_README.md`

Then:

```powershell
cd BackEnd
python -m pip install -r requirements.txt
python -m ml.training.train_all --data-root "C:\path\to\datasets"
```

## Runtime

```powershell
cd BackEnd
python -m pip install -r requirements.txt
python app.py
```

Serve `FrontEnd/` with the same local web-server method used by the existing project.

## Important implementation note

The existing API integrations were preserved. ML is added as local evidence and, where appropriate, contributes to the existing score/verdict logic.

For email, SMS, ransomware and OCR-derived URL/email/SMS inputs, local ML runs alongside the existing architecture.

For the new File Analyzer, the local ML classifier is the primary classification mechanism.

## Limitations

- The models are trained on public benchmark-style datasets supplied for this build.
- Dataset-specific high scores do not prove production-level generalization.
- The malicious-file model is a static PE classifier, not a full antivirus/EDR replacement.
- The ransomware model uses the first 1024 bytes of PE files because that matches the supplied ransomware dataset.
- The URL model uses reproducible lexical URL features rather than live WHOIS/traffic features.
- No malware/ransomware binary was executed during the build or testing.

## Verification performed

- Python syntax compilation passed for the final source tree.
- JavaScript syntax check passed.
- All five saved model artifacts loaded successfully.
- ML status endpoint returned all five models as available.
- End-to-end safe PE upload test passed.
- File upload validation tests covered malformed/unsupported/empty/oversized/path-traversal cases and quarantine flow in the build verification.

## Frontend polish update

The AI Malicious File Analyzer UI was refined without changing the platform's existing visual language. The update adds:

- Green Safe, amber Suspicious, and red Dangerous result states.
- A visual threat-score meter.
- Explicit Local ML Engine / Static Analysis Only indicators.
- Live ML model availability status.
- Clean file identity and static-analysis summaries.
- Clear "Why this result?" evidence points.
- Recommended action and safety/limitations sections.
- Full report view with ML, static-analysis, identity, and quarantine details.
- Print/Save and plain-text report download.
- Copy-to-clipboard for SHA-256.
- Client-side file type, empty-file, and 50 MB size checks before upload.
- Drag-and-drop highlighting and an "Analyze Another File" flow.

The backend file-analysis response now includes structured assessment explanations and static-analysis summary fields so the frontend can present the result cleanly without guessing what the model or parser found.


## Single-Server Frontend

The Phase 2 build serves the existing `FrontEnd/` directory directly from Flask. The application is intentionally kept as a single-server local setup:

```text
Browser
   ↓
http://127.0.0.1:5000
   ↓
Flask backend + existing FrontEnd
```

No Live Server or separate frontend server is required. The root route serves `FrontEnd/index.html`, and the same Flask process serves the existing HTML pages, CSS, JavaScript and images.
