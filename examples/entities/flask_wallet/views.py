import logging

from cryptojwt import JWT
from cryptojwt.utils import b64e
from fedservice.entity import get_verified_trust_chains
from flask import Blueprint
from flask import current_app
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask.helpers import send_from_directory
from idpyoidc.client.defaults import CC_METHOD
from idpyoidc.util import rndstr
from idpysdjwt.verifier import display_sdjwt
import werkzeug

from openid4v.message import WalletInstanceAttestationJWT

logger = logging.getLogger(__name__)

entity = Blueprint('entity', __name__, url_prefix='')

# Constants
PID_ISSUER_TO_USE = "https://127.0.0.1:6001"
WALLET_ID = "https://127.0.0.1:5005"

def hash_func(value):
    _hash_method = CC_METHOD["S256"]
    _hv = _hash_method(value.encode()).digest()
    return b64e(_hv).decode("ascii")


def compact(qsdict):
    res = {}
    for key, val in qsdict.items():
        if len(val) == 1:
            res[key] = val[0]
        else:
            res[key] = val
    return res


@entity.route('/static/<path:path>')
def send_js(path):
    return send_from_directory('static', path)


@entity.route('/')
def index():
    # only one
    trust_anchor_id = list(current_app.federation_entity.trust_anchors.keys())[0]
    response = current_app.federation_entity.client.do_request(
        "entity_configuration", request_args={"entity_id": trust_anchor_id})

    resolver_endpoint = response["metadata"]["federation_entity"]["federation_resolve_endpoint"]
    session["resolver_endpoint"] = resolver_endpoint

    return render_template('a1_trust_anchor_config.html',
                           ec=response,
                           resolver_endpoint=resolver_endpoint)


@entity.route('/a2_wp_resolved')
def wallet_provider():
    wp_id = request.args["entity_id"]
    if wp_id.endswith('/'):
        wp_id = wp_id[:-1]
    session["wallet_provider_id"] = wp_id
    # Use the resolver endpoint
    trust_anchor_id = list(current_app.federation_entity.trust_anchors.keys())[0]
    query = {'sub': wp_id, 'anchor': trust_anchor_id}
    response = current_app.federation_entity.client.do_request(
        "resolve", request_args=query, endpoint=session["resolver_endpoint"])

    session["wir_endpoint"] = response["metadata"]["wallet_provider"]["token_endpoint"]
    return render_template('a2_wp_resolved.html', response=response,
                           token_endpoint=session["wir_endpoint"])


def construct_wir(ephemeral_key, entity_id, wp_id):
    request_args = {
        "challenge": "__not__applicable__",
        "hardware_signature": "__not__applicable__",
        "integrity_assertion": "__not__applicable__",
        "hardware_key_tag": "__not__applicable__",
        "authorization_endpoint": "__not__applicable__",
        "response_types_supported": "__not__applicable__",
        "response_modes_supported": "__not__applicable__",
        "request_object_signing_alg_values_supported": "__not__applicable__"
    }
    request_args.update({
        "aud": wp_id,
        "iss": f"{entity_id}/{ephemeral_key.kid}",
        "vp_formats_supported": {
            "jwt_vc_json": {
                "alg_values_supported": [
                    "ES256K",
                    "ES384"
                ]
            },
            "jwt_vp_json": {
                "alg_values_supported": [
                    "ES256K",
                    "EdDSA"
                ]
            }
        },
        "cnf": ephemeral_key.serialize(private=False)
    })
    return request_args


@entity.route('/a3_wallet_instance_request')
def wallet_instance_request():
    wallet_entity = current_app.server["wallet"]
    _ephemeral_key_tag = wallet_entity.mint_ephemeral_key()
    session["ephemeral_key_tag"] = _ephemeral_key_tag
    _ephemeral_key = wallet_entity.context.ephemeral_key[_ephemeral_key_tag]
    request_args = construct_wir(_ephemeral_key, wallet_entity.entity_id,
                                 session["wallet_provider_id"])
    return render_template('a3_wallet_instance_request.html', request_args=request_args)


@entity.route('/a4_wallet_instance_attestation')
def wallet_instance_attestation():
    # This is where the attestation request is constructed and sent to the Wallet Provider.
    # And where the response is unpacked.
    wallet_entity = current_app.server["wallet"]
    wallet_provider_id = session["wallet_provider_id"]

    _ephemeral_key_tag = session["ephemeral_key_tag"]
    _ephemeral_key = wallet_entity.context.ephemeral_key[_ephemeral_key_tag]
    request_args = construct_wir(_ephemeral_key, wallet_entity.entity_id, wallet_provider_id)

    _srv = wallet_entity.get_service("wallet_instance_attestation")
    _srv.wallet_provider_id = wallet_provider_id

    # This is where the request is actually sent
    resp = wallet_entity.do_request(
        "wallet_instance_attestation",
        request_args=request_args,
        ephemeral_key=_ephemeral_key,
        endpoint=session['wir_endpoint']
    )

    wallet_instance_attestation = resp["assertion"]

    _jwt = JWT(key_jar=wallet_entity.keyjar)
    _jwt.msg_cls = WalletInstanceAttestationJWT
    _ass = _jwt.unpack(token=wallet_instance_attestation)
    session["thumbprint_in_cnf_jwk"] = _ass["cnf"]["jwk"]["kid"]

    return render_template('a4_wallet_instance_attestation.html',
                           request_args=request_args,
                           wallet_instance_attestation=_ass,
                           response_headers=_ass.jws_header)


@entity.route('/a5_picking_pid_issuer')
def picking_pid_issuer_abbr():
    return render_template('a5_picking_pid_issuer.html',
                           pid_issuer_to_use=PID_ISSUER_TO_USE)

### Credential Issuer conversation part

@entity.route('/authz')
def authz():
    actor = current_app.server["pid_eaa_consumer"]
    _actor = actor.get_consumer(PID_ISSUER_TO_USE)
    if _actor is None:
        actor = actor.new_consumer(PID_ISSUER_TO_USE)
    else:
        actor = _actor

    b64hash = hash_func(PID_ISSUER_TO_USE)
    _redirect_uri = f"{WALLET_ID}/authz_cb/{b64hash}"
    session["redirect_uri"] = _redirect_uri
    _thumbprint = session["thumbprint_in_cnf_jwk"]
    wallet_entity = current_app.server["wallet"]
    request_args = {
        "authorization_details": [
            {
                "type": "openid_credential",
                "format": "vc+sd-jwt",
                "credential_definition": {
                    "type": "PersonIdentificationData"
                }
            }
        ],
        "response_type": "code",
        "client_id": _thumbprint,
        "redirect_uri": _redirect_uri,
        "client_assertion": wallet_entity.context.wallet_instance_attestation[_thumbprint][
            "attestation"]
    }
    kwargs = {
        "state": rndstr(24),
        # "entity_id": pid_issuer
    }
    session["state"] = kwargs["state"]

    _service = actor.get_service("authorization")
    _service.certificate_issuer_id = PID_ISSUER_TO_USE

    req_info = _service.get_request_parameters(request_args, **kwargs)

    logger.info(f"Redirect to: {req_info['url']}")
    response = redirect(req_info["url"], 303)
    return response


def get_consumer(issuer):
    actor = current_app.server["pid_eaa_consumer"]
    _consumer = None
    for iss in actor.issuers():
        if hash_func(iss) == issuer:
            _consumer = actor.get_consumer(iss)
            break

    return _consumer


@entity.route('/authz_cb/<issuer>')
def authz_cb(issuer):
    _consumer = get_consumer(issuer)

    # if _consumer is None
    # -- some error message

    _consumer.finalize_auth(request.args)
    session["issuer"] = issuer
    return render_template('authorization.html', response=request.args.to_dict())


@entity.route('/token')
def token():
    consumer = get_consumer(session["issuer"])
    _req_args = consumer.context.cstate.get_set(session["state"], claim=["redirect_uri", "code",
                                                                         "nonce"])
    trust_chains = get_verified_trust_chains(consumer, consumer.context.issuer)
    trust_chain = trust_chains[0]
    _thumbprint = session["thumbprint_in_cnf_jwk"]
    wallet_entity = current_app.server["wallet"]
    _args = {
        "audience": consumer.context.issuer,
        "thumbprint": _thumbprint,
        "wallet_instance_attestation":
            wallet_entity.context.wallet_instance_attestation[_thumbprint]["attestation"],
        "signing_key": wallet_entity.keyjar.get_signing_key(kid=_thumbprint)[0]
    }
    _nonce = _req_args.get("nonce", "")
    if _nonce:
        _args["nonce"] = _nonce
    _lifetime = consumer.context.config["conf"].get("jwt_lifetime")
    if _lifetime:
        _args["lifetime"] = _lifetime

    resp = consumer.do_request(
        "accesstoken",
        request_args={
            "code": _req_args["code"],
            "grant_type": "authorization_code",
            "redirect_uri": _req_args["redirect_uri"],
            "state": session["state"]
        },
        endpoint=trust_chain.metadata['openid_credential_issuer']['token_endpoint'],
        state=session["state"],
        **_args
    )

    return render_template('token.html', response=resp)


@entity.route('/credential')
def credential():
    consumer = get_consumer(session["issuer"])
    _req_args = consumer.context.cstate.get_set(session["state"], claim=["access_token"])
    trust_chains = get_verified_trust_chains(consumer, consumer.context.issuer)
    trust_chain = trust_chains[0]
    resp = consumer.do_request(
        "credential",
        request_args={
            "format": "vc+sd-jwt",
            "credential_definition": {
                "type": ["PersonIdentificationData"]
            }
        },
        access_token=_req_args["access_token"],
        state=session["state"],
        endpoint=trust_chain.metadata['openid_credential_issuer']['credential_endpoint']
    )

    _jwt, _displ = display_sdjwt(resp["credential"])
    return render_template('credential.html', response=resp, signed_jwt=_jwt,
                           display=_displ)


@entity.errorhandler(werkzeug.exceptions.BadRequest)
def handle_bad_request(e):
    return 'bad request!', 400
