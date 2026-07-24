"""Support preview endpoint containing a comparison-only reflected XSS sample."""

from __future__ import annotations

from markupsafe import escape
from flask import Response, request

from auth import VULN


def preview_message():
    """Render a support-message preview.

    In vulnerable mode the query parameter is inserted directly into HTML. The
    secure branch escapes the same value, providing an explicit differential GT.
    """
    message = request.args.get("message", "")
    rendered = message if VULN else str(escape(message))
    return Response(f"<html><body><p>{rendered}</p></body></html>", mimetype="text/html")
