from flask import Blueprint
from controllers.ransomware_controller import scan_ransomware

ransomware_bp = Blueprint("ransomware", __name__)

ransomware_bp.route("/ransomware", methods=["POST"])(scan_ransomware)