from flask import Blueprint

from controllers.scan_controller import (
    scan_url,
    get_scan_history,
    clear_scan_history
)


scan_bp = Blueprint(
    "scan",
    __name__
)


scan_bp.route(
    "/url",
    methods=["POST"]
)(scan_url)


scan_bp.route(
    "/history",
    methods=["GET"]
)(get_scan_history)


scan_bp.route(
    "/history",
    methods=["DELETE"]
)(clear_scan_history)