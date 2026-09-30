from flask import Blueprint
from controllers.sms_controller import scan_sms

sms_bp = Blueprint("sms", __name__)

sms_bp.route("/sms", methods=["POST"])(scan_sms)