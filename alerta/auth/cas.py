from cas import CASClient
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
    try:
        ticket = request.json['ticket']
        service = request.json['service']
    except (KeyError, TypeError):
        raise ApiError("must supply 'ticket' and 'service'", 400)

    client = CASClient(
        version=current_app.config.get('CAS_VERSION', '3'),
        server_url=current_app.config['CAS_SERVER_URL'],
        service_url=service,
        renew=current_app.config.get('CAS_RENEW', False),
        verify_ssl_certificate=current_app.config.get('CAS_VERIFY_SSL', True)
    )

    try:
        username, attributes, _ = client.verify_ticket(ticket)
    except Exception:
        raise ApiError('invalid CAS ticket', 401)

    if not username:
        raise ApiError('invalid CAS ticket', 401)

    login = attributes.get(current_app.config.get('CAS_USERNAME_ATTRIBUTE'), username) if attributes else username
    name = attributes.get('name') if attributes else login
    email = attributes.get('email') if attributes else None
    groups = attributes.get('groups') if attributes else []
    roles = attributes.get('roles') if attributes else []

    if groups and not isinstance(groups, list):
        groups = [groups]
    if roles and not isinstance(roles, list):
        roles = [roles]

    user = User.find_by_username(username=login)
    if not user:
        user = User(name=name, login=login, password='', email=email,
                    roles=current_app.config['USER_ROLES'], text='CAS user',
                    email_verified=bool(email))
        user.create()
    else:
        user.update(login=login, email=email, email_verified=bool(email))

    if user.status != 'active':
        raise ApiError(f'User {login} is not active', 403)

    if not_authorized('ALLOWED_EMAIL_DOMAINS', groups=[user.domain]):
        raise ApiError(f'User {login} is not authorized', 403)
    user.update_last_login()

    scopes = Permission.lookup(login, roles=user.roles + roles + groups)
    customers = get_customers(login, groups=groups + ([user.domain] if user.domain else []))

    auth_audit_trail.send(current_app._get_current_object(), event='cas-login', message='user login via CAS',
                          user=login, customers=customers, scopes=scopes, roles=user.roles, groups=groups,
                          resource_id=user.id, type='user', request=request)

    token = create_token(user_id=user.id, name=name, login=login, provider='cas',
                         customers=customers, scopes=scopes, roles=user.roles + roles, groups=groups,
                         email=email, email_verified=bool(email))
    return jsonify(token=token.tokenize())
