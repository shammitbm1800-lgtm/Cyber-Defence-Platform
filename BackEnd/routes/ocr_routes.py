from flask import Blueprint
from controllers.ocr_controller import scan_image

ocr_bp = Blueprint("ocr", __name__)

ocr_bp.route("/url/image", methods=["POST"])(scan_image)
ocr_bp.route("/email/image", methods=["POST"])(scan_image)
ocr_bp.route("/sms/image", methods=["POST"])(scan_image)