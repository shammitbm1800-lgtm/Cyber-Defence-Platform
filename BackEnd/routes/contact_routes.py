from flask import Blueprint

from controllers.contact_controller import send_contact_inquiry


contact_bp = Blueprint(
    "contact",
    __name__
)


contact_bp.route(
    "/contact",
    methods=["POST"]
)(
    send_contact_inquiry
)