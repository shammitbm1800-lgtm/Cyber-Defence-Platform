from flask import Blueprint
from controllers.email_controller import scan_email

email_bp = Blueprint("email", __name__)

email_bp.route("/email", methods=["POST"])(scan_email)