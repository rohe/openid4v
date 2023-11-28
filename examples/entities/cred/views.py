import json
import os
import sys
import traceback
from typing import Union
from urllib.parse import urlparse

import werkzeug
from flask import Blueprint
from flask import current_app
from flask import redirect
from flask import render_template
from flask import request
from flask import Response
from flask.helpers import make_response
from flask.helpers import send_from_directory
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.message.oidc import AccessTokenRequest
from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.server.exception import ClientAuthenticationError
from idpyoidc.server.exception import FailedAuthentication
from idpyoidc.server.oidc.token import Token

# logger = logging.getLogger(__name__)

entity = Blueprint('oidc_op', __name__, url_prefix='')


def _add_cookie(resp: Response, cookie_spec: Union[dict, list]):
    kwargs = {k: v
              for k, v in cookie_spec.items()
              if k not in ('name',)}
    kwargs["path"] = "/"
    kwargs["samesite"] = "Lax"
    resp.set_cookie(cookie_spec["name"], **kwargs)


def add_cookie(resp: Response, cookie_spec: Union[dict, list]):
    if isinstance(cookie_spec, list):
        for _spec in cookie_spec:
            _add_cookie(resp, _spec)
    elif isinstance(cookie_spec, dict):
        _add_cookie(resp, cookie_spec)


@entity.route('/static/<path:path>')
def send_js(path):
    return send_from_directory('static', path)


@entity.route('/keys/<jwks>')
def keys(jwks):
    fname = os.path.join('static', jwks)
    return open(fname).read()


@entity.route('/')
def index():
    return render_template('index.html')


# def add_headers_and_cookie(resp, info):
#     return resp


def do_response(endpoint, req_args, error='', **args) -> Response:
    info = endpoint.do_response(request=req_args, error=error, **args)
    _log = current_app.logger
    _log.debug('do_response: {}'.format(info))

    try:
        _response_placement = info['response_placement']
    except KeyError:
        _response_placement = endpoint.response_placement

    _log.debug('response_placement: {}'.format(_response_placement))

    if error:
        if _response_placement == 'body':
            _log.info('Error Response: {}'.format(info['response']))
            _http_response_code = info.get('response_code', 400)
            resp = make_response(info['response'], _http_response_code)
        else:  # _response_placement == 'url':
            _log.info('Redirect to: {}'.format(info['response']))
            resp = redirect(info['response'])
    else:
        if _response_placement == 'body':
            _log.info('Response: {}'.format(info['response']))
            _http_response_code = info.get('response_code', 200)
            resp = make_response(info['response'], _http_response_code)
        else:  # _response_placement == 'url':
            _log.info('Redirect to: {}'.format(info['response']))
            resp = redirect(info['response'])

    for key, value in info['http_headers']:
        resp.headers[key] = value

    if 'cookie' in info:
        add_cookie(resp, info['cookie'])

    return resp


def verify(authn_method):
    """
    Authentication verification

    :param url_endpoint: Which endpoint to use
    :param kwargs: response arguments
    :return: HTTP redirect
    """

    kwargs = dict([(k, v) for k, v in request.form.items()])
    username = authn_method.verify(**kwargs)
    if not username:
        return make_response('Authentication failed', 403)

    auth_args = authn_method.unpack_token(kwargs['token'])
    authz_request = AuthorizationRequest().from_urlencoded(auth_args['query'])

    endpoint = current_app.server.get_endpoint('authorization')
    _session_id = endpoint.create_session(authz_request, username, auth_args['authn_class_ref'],
                                          auth_args['iat'], authn_method)

    args = endpoint.authz_part2(request=authz_request, session_id=_session_id)

    if isinstance(args, ResponseMessage) and 'error' in args:
        return make_response(args.to_json(), 400)

    return do_response(endpoint, request, **args)


@entity.route('/verify/user', methods=['GET', 'POST'])
def verify_user():
    authn_method = current_app.server.get_context().authn_broker.get_method_by_id('user')
    try:
        return verify(authn_method)
    except FailedAuthentication as exc:
        return render_template("error.html", title=str(exc))


@entity.route('/verify/user_pass_jinja', methods=['GET', 'POST'])
def verify_user_pass_jinja():
    authn_method = current_app.server.get_context().authn_broker.get_method_by_id('user')
    try:
        return verify(authn_method)
    except FailedAuthentication as exc:
        return render_template("error.html", title=str(exc))


@entity.route('/.well-known/openid-federation')
def wkof():
    _srv = current_app.server
    metadata = _srv.get_metadata()
    _ctx = current_app.federation_entity.context
    iss = sub = _ctx.entity_id
    _statement = _ctx.create_entity_statement(
        metadata=metadata,
        iss=iss, sub=sub, authority_hints=_ctx.authority_hints,
        lifetime=_ctx.default_lifetime)

    response = make_response(_statement)
    response.headers['Content-Type'] = 'application/jose; charset=UTF-8'
    return response


@entity.route('/pushed_authorization', methods=['POST'])
def pushed_authorization():
    _endpoint = current_app.server["openid_credential_issuer"].get_endpoint('pushed_authorization')
    return service_endpoint(_endpoint)

@entity.route('/authorization')
def authorization():
    _endpoint = current_app.server["openid_credential_issuer"].get_endpoint('authorization')
    return service_endpoint(_endpoint)


@entity.route('/token', methods=['GET', 'POST'])
def token():
    return service_endpoint(
        current_app.server["openid_credential_issuer"].get_endpoint('token'))


@entity.route('/credential', methods=['POST'])
def introspection_endpoint():
    endpoint = current_app.server["openid_credential_issuer"].get_endpoint('credential')
    return service_endpoint(endpoint)


IGNORE = ["cookie", "user-agent"]


def service_endpoint(endpoint):
    _log = current_app.logger
    _log.info('At the "{}" endpoint'.format(endpoint.name))

    http_info = {
        "headers": {k: v for k, v in request.headers.items(lower=True) if k not in IGNORE},
        "method": request.method,
        "url": request.url,
        # name is not unique
        "cookie": [{"name": k, "value": v} for k, v in request.cookies.items()]
    }
    _log.info(f"http_info: {http_info}")

    if request.method == 'GET':
        try:
            req_args = endpoint.parse_request(request.args.to_dict(), http_info=http_info)
        except ClientAuthenticationError as err:
            _log.error(err)
            return make_response(json.dumps({
                'error': 'unauthorized_client',
                'error_description': str(err)
            }), 401)
        except Exception as err:
            _log.error(err)
            return make_response(json.dumps({
                'error': 'invalid_request',
                'error_description': str(err)
            }), 400)
    else:
        if request.data:
            if isinstance(request.data, (str, bytes)):
                try:
                    req_args = json.loads(request.data)
                except Exception as err:
                    req_args = request.data
            else:
                req_args = request.data.decode()
        else:
            req_args = dict([(k, v) for k, v in request.form.items()])
        try:
            req_args = endpoint.parse_request(req_args, http_info=http_info)
        except Exception as err:
            _log.error(err)
            err_msg = ResponseMessage(error='invalid_request', error_description=str(err))
            return make_response(err_msg.to_json(), 400)

    if isinstance(req_args, ResponseMessage) and 'error' in req_args:
        _log.info('Error response: {}'.format(req_args))
        _resp = make_response(req_args.to_json(), 400)
        if request.method == "POST":
            _resp.headers["Content-type"] = "application/json"
        return _resp
    try:
        _log.info('request: {}'.format(req_args))
        if isinstance(endpoint, Token):
            args = endpoint.process_request(AccessTokenRequest(**req_args), http_info=http_info)
        else:
            args = endpoint.process_request(req_args, http_info=http_info)
    except Exception as err:
        message = traceback.format_exception(*sys.exc_info())
        _log.error(message)
        err_msg = ResponseMessage(error='invalid_request', error_description=str(err))
        return make_response(err_msg.to_json(), 400)

    _log.info('Response args: {}'.format(args))

    if 'redirect_location' in args:
        return redirect(args['redirect_location'])
    if 'http_response' in args:
        return make_response(args['http_response'], 200)

    response = do_response(endpoint, req_args, **args)
    return response


@entity.errorhandler(werkzeug.exceptions.BadRequest)
def handle_bad_request(e):
    return 'bad request!', 400


@entity.route('/verify_logout', methods=['GET', 'POST'])
def verify_logout():
    part = urlparse(current_app.server.get_context().issuer)
    page = render_template('logout.html', op=part.hostname,
                           do_logout='rp_logout', sjwt=request.args['sjwt'])
    return page
