from flask import Blueprint
from controllers.file_controller import scan_malicious_file, ml_status

file_bp = Blueprint("file_analysis", __name__)
file_bp.route("/file", methods=["POST"])(scan_malicious_file)
file_bp.route("/ml-status", methods=["GET"])(ml_status)
