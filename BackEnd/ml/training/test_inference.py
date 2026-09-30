"""Safe inference smoke tests for the five ML models.

This test uses text/URL fixtures and project-local executable fixtures when
available. It never executes the uploaded/test binaries.
"""
from pathlib import Path
from ml.predictors import predict_url, predict_email, predict_sms, predict_ransomware_file, predict_malicious_file

def main():
    print("URL:", predict_url("https://example.com/login")["label"])
    print("EMAIL:", predict_email("Please verify your account immediately.")["label"])
    print("SMS:", predict_sms("Congratulations! You won a free prize. Reply now.")["label"])

    candidates = list(Path(__file__).resolve().parents[2].rglob("*.exe"))
    if candidates:
        path = str(candidates[0])
        print("Ransomware ML:", predict_ransomware_file(path)["label"])
        file_pred, info = predict_malicious_file(path)
        print("Malicious-file ML:", file_pred["label"], "PE sections:", len(info.get("sections", [])))

if __name__ == "__main__":
    main()
