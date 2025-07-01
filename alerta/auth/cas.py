import xml.etree.ElementTree as ET
import requests
from flask import current_app, jsonify, request
from flask_cors import cross_origin

from alerta.auth.utils import create_token, get_customers, not_authorized
from alerta.exceptions import ApiError
from alerta.models.permission import Permission
from alerta.models.user import User
from alerta.utils.audit import auth_audit_trail

from . import auth


@auth.route('/auth/cas', methods=['OPTIONS', 'POST'])
@cross_origin(supports_credentials=True)
def cas_login():
    cas_validate_url = current_app.config['CAS_VALIDATE_URL']
    if not cas_validate_url:
        raise ApiError('CAS validation URL not configured', 503)

    try:
        ticket = request.json['ticket']
        service = request.json['service']
    except Exception:
        raise ApiError("must supply 'ticket' and 'service'", 400)

    try:
        r = requests.get(cas_validate_url, params={'service': service, 'ticket': ticket}, timeout=2)
    except Exception as e:
        raise ApiError(f'CAS validation failed: {e}', 503)

    if r.status_code != 200:
        raise ApiError('CAS validation failed', 503)

    try:
        root = ET.fromstring(r.text)
    except Exception:
        raise ApiError('CAS response invalid', 503)

    ns = {'cas': 'http://www.yale.edu/tp/cas'}
    username = root.findtext('.//cas:user', namespaces=ns)
    if not username:
        raise ApiError('CAS authentication failed', 401)

    attrs_elem = root.find('.//cas:attributes', namespaces=ns)
    attrs = {}
    if attrs_elem is not None:
        for elem in attrs_elem:
            tag = elem.tag.split('}', 1)[-1]
            attrs[tag] = elem.text

    name = attrs.get(current_app.config['CAS_NAME_ATTRIBUTE']) or username
    email = attrs.get(current_app.config['CAS_EMAIL_ATTRIBUTE'])
    groups = []
    groups_attr = attrs.get(current_app.config['CAS_GROUPS_ATTRIBUTE'])
    if groups_attr:
        groups = [g.strip() for g in groups_attr.split(',') if g.strip()]

    user = User.find_by_username(username=username)
    if not user:
        user = User(name=name, login=username, password='', email=email,
                    roles=current_app.config['USER_ROLES'], text='CAS user', email_verified=True)
        user.create()
    else:
        user.update(login=username, email=email)

    if user.status != 'active':
        raise ApiError(f'User {username} is not active', 403)

    if not_authorized('ALLOWED_CAS_GROUPS', groups) or not_authorized('ALLOWED_EMAIL_DOMAINS', groups=[user.domain]):
        raise ApiError(f'User {username} is not authorized', 403)
    user.update_last_login()

    scopes = Permission.lookup(login=user.login, roles=user.roles + groups)
    customers = get_customers(login=user.login, groups=groups + ([user.domain] if user.domain else []))

    auth_audit_trail.send(current_app._get_current_object(), event='cas-login', message='user login via CAS',
                          user=user.login, customers=customers, scopes=scopes, roles=user.roles, groups=groups,
                          resource_id=user.id, type='user', request=request)

    token = create_token(user_id=user.id, name=user.name, login=user.login, provider='cas',
                         customers=customers, scopes=scopes, roles=user.roles, groups=groups,
                         email=user.email, email_verified=user.email_verified)
    return jsonify(token=token.tokenize())
