import json
import os
import time
from pathlib import Path

from flask import current_app, jsonify, request, session

from models import db, Scan
from services.file_analysis_service import analyze_uploaded_file, MAX_FILE_SIZE
from services.quarantine_service import quarantine_file
from services.ransomware_behavior_service import RansomwareBehaviorMonitor
from watchdog.observers import Observer


def scan_malicious_file():
    if not session.get("user_id"):
        return jsonify({
            "status": "error",
            "message": "Authentication required"
        }), 401

    if "file" not in request.files:
        return jsonify({
            "status": "error",
            "message": "File is required"
        }), 400

    uploaded = request.files["file"]

    if not uploaded.filename:
        return jsonify({
            "status": "error",
            "message": "No file selected"
        }), 400

    if request.content_length and request.content_length > MAX_FILE_SIZE + 1024 * 1024:
        return jsonify({
            "status": "error",
            "message": "Upload is too large"
        }), 413

    temp_root = Path(
        request.environ.get("TMPDIR")
        or os.getenv("TEMP")
        or "/tmp"
    )

    temp_root.mkdir(
        parents=True,
        exist_ok=True
    )

    temp_path = temp_root / f"cdf_upload_{os.getpid()}_{id(uploaded)}.bin"

    try:
        uploaded.save(temp_path)

        result = analyze_uploaded_file(
            str(temp_path),
            uploaded.filename
        )

        quarantine_requested = str(
            request.form.get("quarantine", "")
        ).lower() in ("1", "true", "yes", "on")

        quarantine_result = {
            "quarantined": False
        }

        if quarantine_requested:
            quarantine_root = (
                Path(__file__).resolve().parents[1]
                / "instance"
                / "quarantine"
            )

            quarantine_root.mkdir(
                parents=True,
                exist_ok=True
            )

            watchdog_result = {
                "monitoring": False,
                "created": 0,
                "modified": 0,
                "deleted": 0,
                "moved": 0,
                "total_events": 0
            }

            observer = None

            try:
                handler = RansomwareBehaviorMonitor(
                    window_seconds=5
                )

                observer = Observer()

                observer.schedule(
                    handler,
                    str(quarantine_root),
                    recursive=False
                )

                observer.start()

                # Give Watchdog a moment to start before quarantine.
                time.sleep(0.2)

                quarantine_result = quarantine_file(
                    str(temp_path),
                    str(quarantine_root),
                    uploaded.filename
                )

                # Allow the filesystem event to reach Watchdog.
                time.sleep(0.5)

                watchdog_result = {
                    "monitoring": True,
                    **handler.get_activity_summary()
                }

            except Exception:
                # Watchdog must never break the existing quarantine flow.
                watchdog_result = {
                    "monitoring": False,
                    "created": 0,
                    "modified": 0,
                    "deleted": 0,
                    "moved": 0,
                    "total_events": 0
                }

            finally:
                if observer is not None:
                    observer.stop()
                    observer.join(timeout=2)

            quarantine_result["watchdog"] = watchdog_result

        new_scan = Scan(
            scan_type="malicious_file",
            input_content=uploaded.filename,
            filename=uploaded.filename,
            sha256=result["sha256"],
            final_verdict=result["verdict"],
            internal_score=int(result["score"]),
            confidence=result.get("confidence", "model"),
            reasons=json.dumps(result.get("reasons", [])),
            api_results=json.dumps({
                "ml": result.get("ml", {}),
                "static_analysis": result.get("static_analysis", {})
            })
        )

        db.session.add(new_scan)
        db.session.commit()

        result["quarantine"] = {
            "requested": quarantine_requested,
            **quarantine_result
        }

        result["scan_id"] = new_scan.id

        return jsonify({
            "status": "success",
            "result": result
        })

    except Exception as exc:
        db.session.rollback()

        return jsonify({
            "status": "error",
            "message": str(exc)
        }), 500

    finally:
        try:
            if temp_path.exists():
                temp_path.unlink()
        except Exception:
            pass

def ml_status():
    from ml.model_registry import model_status
    models = model_status()
    return jsonify({
        "status": "available" if any(item.get("available") for item in models.values()) else "unavailable",
        "models": models,
        "file_analyzer": {
            "supported_ml_types": ["PE", "PDF", "ELF"],
            "execution": "never",
        },
    })