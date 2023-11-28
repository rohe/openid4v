import logging

from cryptojwt.jws.jws import factory
from idpysdjwt.verifier import display_sdjwt
import werkzeug
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

from openid4v.message import WalletInstanceAttestationJWT

logger = logging.getLogger(__name__)

entity = Blueprint('entity', __name__, url_prefix='')


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
    return render_template('base.html')


@entity.route('/wallet_provider')
def wallet_provider():
    wp_id = request.args["entity_id"]
    session["wallet_provider_id"] = wp_id
    trust_chain = current_app.federation_entity.get_trust_chain(wp_id)

    return render_template('wallet_provider.html',
                           trust_chain_path=trust_chain.iss_path,
                           metadata=trust_chain.metadata)


@entity.route('/wallet_instance_attestation')
def wallet_instance_attestation():
    # This is where the attestation request is constructed and sent to the Wallet Provider.
    # And where the response is unpacked.
    wallet_entity = current_app.server["wallet"]
    wallet_provider_id = session["wallet_provider_id"]

    trust_chain = current_app.federation_entity.get_trust_chain(wallet_provider_id)

    _service = wallet_entity.get_service("wallet_instance_attestation")
    _service.wallet_provider_id = wallet_provider_id

    request_args = {"nonce": rndstr(), "aud": wallet_provider_id}

    # this is just to be able to show what's sent
    req_info = _service.get_request_parameters(
        request_args,
        endpoint=trust_chain.metadata['wallet_provider']['token_endpoint'])
    _ra_jwt = factory(req_info["request"]["assertion"])
    req_assertion = _ra_jwt.jwt.payload()

    # This is where the request is actually sent
    resp = wallet_entity.do_request(
        "wallet_instance_attestation",
        request_args=request_args,
        endpoint=trust_chain.metadata['wallet_provider']['token_endpoint'])

    wallet_instance_attestation = resp["assertion"]

    _jwt = JWT(key_jar=wallet_entity.keyjar)
    _jwt.msg_cls = WalletInstanceAttestationJWT
    _ass = _jwt.unpack(token=wallet_instance_attestation)
    session["thumbprint_in_cnf_jwk"] = _ass["cnf"]["jwk"]["kid"]

    return render_template('wallet_instance_attestation.html',
                           req_assertion = req_assertion,
                           request_headers=_ra_jwt.jwt.headers,
                           req_info=req_info,
                           wallet_instance_attestation=_ass,
                           response_headers=_ass.jws_header)


@entity.route('/picking_pid_issuer')
def picking_pid_issuer():
    res = []
    ta_id = list(current_app.federation_entity.trust_anchors.keys())[0]
    list_resp = current_app.federation_entity.do_request('list', entity_id=ta_id)
    # print(f"Subordinates to TA: {list_resp}")
    for entity_id in list_resp:
        res.extend(
            current_app.federation_entity.trawl(ta_id, entity_id,
                                                entity_type="openid_credential_issuer"))

    credential_issuers = res

    _oci = {}
    credential_type = "PersonIdentificationData"
    for pid in res:
        oci_metadata = current_app.federation_entity.get_verified_metadata(pid)
        # logger.info(json.dumps(oci_metadata, sort_keys=True, indent=4))
        for cs in oci_metadata['openid_credential_issuer']["credentials_supported"]:
            if credential_type in cs["credential_definition"]["type"]:
                _oci[pid] = oci_metadata
                break

    pid_issuers = list(_oci.keys())

    pid_issuer_to_use = []
    tmi = {}
    se_pid_issuer_tm = 'http://dc4eu.example.com/PersonIdentificationData/se'
    for eid, metadata in _oci.items():
        _trust_chain = current_app.federation_entity.get_trust_chain(eid)
        _ec = _trust_chain.verified_chain[-1]
        if "trust_marks" in _ec:
            tmi[eid] = []
            for _mark in _ec["trust_marks"]:
                _verified_trust_mark = current_app.federation_entity.verify_trust_mark(
                    _mark, check_with_issuer=True)
                tmi[eid].append(_verified_trust_mark)
                if _verified_trust_mark.get("id") == se_pid_issuer_tm:
                    pid_issuer_to_use.append(eid)

    session["pid_issuer_to_use"] = pid_issuers[0]

    return render_template('picking_pid_issuer.html',
                           credential_issuers=credential_issuers,
                           pid_issuers=pid_issuers,
                           trust_marks=tmi,
                           pid_issuer_to_use=pid_issuer_to_use)


@entity.route('/authz')
def authz():
    pid_issuer = session["pid_issuer_to_use"]
    actor = current_app.server["pid_eaa_consumer"]
    _actor = actor.get_consumer(pid_issuer)
    if _actor is None:
        actor = actor.new_consumer(pid_issuer)
    else:
        actor = _actor

    b64hash = hash_func(pid_issuer)
    _redirect_uri = f"https://127.0.0.1:5005/authz_cb/{b64hash}"
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
    _service.certificate_issuer_id = pid_issuer

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
