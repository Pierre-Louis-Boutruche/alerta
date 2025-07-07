"""
CAS authentication provider for Alerta.
Validates a CAS ticket, creates/updates the User, and returns an Alerta JWT token.
"""

import logging
import requests
import xml.etree.ElementTree as ET

from flask import current_app, jsonify, request
from flask_cors import cross_origin

from alerta.auth.utils import create_token, get_customers, not_authorized
from alerta.exceptions import ApiError
from alerta.models.permission import Permission
from alerta.models.user import User
from alerta.utils.audit import auth_audit_trail

from . import auth   # Blueprint defined in alerta/auth/__init__.py

LOG = logging.getLogger("alerta.auth.cas")


def validate_cas(ticket, service, cas_server, validate_route="/serviceValidate"):
    """
    Validate a CAS ticket by sending an HTTP request to the CAS server.
    Returns (True, username, attributes) if valid, else (False, None, {}).
    """
    url = f"{cas_server.rstrip('/')}{validate_route}?ticket={ticket}&service={service}"
    try:
        resp = requests.get(url, timeout=5)
    except Exception as e:
        LOG.exception("Failed to contact CAS server")
        raise ApiError(f"Unable to contact CAS server: {e}", 503)

    if resp.status_code != 200:
        LOG.error("Invalid CAS response: %s", resp.text)
        return False, None, {}

    try:
        root = ET.fromstring(resp.text)
        ns = {"cas": "http://www.yale.edu/tp/cas"}

        success = root.find("cas:authenticationSuccess", ns)
        if success is None:
            return False, None, {}

        username = success.findtext("cas:user", None, ns)
        attrs = {}
        attr_block = success.find("cas:attributes", ns)
        if attr_block is not None:
            for child in attr_block:
                key = child.tag.split("}", 1)[-1]  # Remove namespace
                attrs[key] = child.text

        return True, username, attrs

    except ET.ParseError as e:
        LOG.exception("Failed to parse CAS XML response")
        raise ApiError(f"Malformed CAS response: {e}", 502)


# ---------------------------------------------------------------------------
# /auth/cas – endpoint called by the frontend
# ---------------------------------------------------------------------------
@auth.route("/auth/cas", methods=["OPTIONS", "POST"])
@cross_origin(supports_credentials=True)
def cas_login():
    """
    Example frontend request:
      POST /auth/cas
      {
        "ticket":  "ST-12345-abcdef",
        "service": "https://alerta.example.com"
      }
    Response: { "token": "<JWT>" }
    """
    if request.method == "OPTIONS":  # CORS pre-flight
        return "", 204

    ticket = request.json.get("ticket")
    service = request.json.get("service")
    if not ticket or not service:
        raise ApiError("Fields 'ticket' and 'service' are required", 400)

    cas_server = current_app.config.get("CAS_SERVER")
    if not cas_server:
        raise ApiError("Missing CAS_SERVER configuration", 500)

    validate_route = current_app.config.get("CAS_VALIDATE_ROUTE", "/serviceValidate")

    success, cas_username, attrs = validate_cas(ticket, service, cas_server, validate_route)

    if not success:
        raise ApiError("Invalid CAS ticket", 401)

    # Map CAS attributes to Alerta User model
    login = cas_username
    email = attrs.get("mail") or attrs.get("email") \
        or f"{login}@{current_app.config.get('DEFAULT_EMAIL_DOMAIN', '')}"
    email_verified = "mail" in attrs or "email" in attrs

    role_claim = current_app.config.get("CAS_ROLE_CLAIM", "roles")
    group_claim = current_app.config.get("CAS_GROUP_CLAIM", "groups")

    roles_from_cas = attrs.get(role_claim, "").split(",") if attrs.get(role_claim) else []
    groups_from_cas = attrs.get(group_claim, "").split(",") if attrs.get(group_claim) else []

    subject = login  # Unique user identifier

    # Create or update user record
    user = User.find_by_id(id=subject)
    if not user:
        user = User(
            id=subject,
            name=attrs.get("displayName", login),
            login=login,
            password="",
            email=email,
            roles=current_app.config["USER_ROLES"],
            text="",
            email_verified=email_verified,
        )
        user.create()
    else:
        user.update(login=login, email=email)

    roles = list(set(roles_from_cas + user.roles))
    groups = groups_from_cas

    # Check user status and optional whitelists
    if user.status != "active":
        raise ApiError(f"User {login} is not active", 403)

    if not_authorized("ALLOWED_EMAIL_DOMAINS", groups=[user.domain]):
        raise ApiError(f"User {login} is not authorized", 403)

    user.update_last_login()

    # Scopes, customers, audit trail, JWT generation
    scopes = Permission.lookup(login, roles=roles)
    customers = get_customers(login, groups=groups + ([user.domain] if user.domain else []))

    auth_audit_trail.send(
        current_app._get_current_object(),
        event="cas-login",
        message="User login via CAS",
        user=login,
        customers=customers,
        scopes=scopes,
        roles=roles,
        groups=groups,
        resource_id=subject,
        type="user",
        request=request,
    )

    token = create_token(
        user_id=subject,
        name=user.name,
        login=login,
        provider="cas",
        customers=customers,
        scopes=scopes,
        roles=roles,
        groups=groups,
        email=email,
        email_verified=email_verified,
        picture=None,
    )

    return jsonify(token=token.tokenize())
