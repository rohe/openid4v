import json
import os
from urllib.parse import quote_plus
from urllib.parse import unquote_plus
from urllib.parse import urlparse

from cryptojwt import JWT
from cryptojwt.jws.utils import alg2keytype
from cryptojwt.jwt import utc_time_sans_frac
from cryptojwt.key_jar import build_keyjar
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
import pytest

from openid4v.message import AuthorizationDetail
from openid4v.message import AuthorizationRequest
from openid4v.message import CredentialDefinition
from openid4v.message import CredentialIssuerMetadata
from openid4v.message import CredentialMetadata
from openid4v.message import CredentialOffer
from openid4v.message import CredentialRequestJwtVcJson
from openid4v.message import DisplayProperty
from openid4v.message import ProofToken

JWT_ISSUER = "s6BhdRkqt3"
KEYJAR = build_keyjar(DEFAULT_KEY_DEFS)
KEYJAR.import_jwks(KEYJAR.export_jwks(private=True), JWT_ISSUER)

_dirname = os.path.dirname(os.path.abspath(__file__))


def test_credential_request():
    payload = {
        "aud": "https://server.example.com",
        "iat": utc_time_sans_frac(),
        "nonce": "tZignsnFbp"
    }
    sign_alg = "ES256"
    _kid = 0
    _possible_keys = KEYJAR.get_signing_key(key_type=alg2keytype(sign_alg), issuer_id=JWT_ISSUER)
    if len(_possible_keys) >= 1:
        _kid = _possible_keys[0].kid

    _headers = {
        "typ": "openid4vci-proof+jwt",
        "jwk": _possible_keys[0].serialize()
    }
    _jwt = JWT(key_jar=KEYJAR, sign_alg=sign_alg, iss=JWT_ISSUER)
    _jws = _jwt.pack(payload, jws_headers=_headers, kid=_kid)

    query = {
        "format": "jwt_vc_json",
        "credential_definition": {
            "type": [
                "VerifiableCredential",
                "UniversityDegreeCredential"
            ]
        },
        "proof": {
            "proof_type": "jwt",
            "jwt": _jws
        }
    }

    cr = CredentialRequestJwtVcJson(**query)
    cr.verify(keyjar=KEYJAR)
    assert isinstance(cr["proof"]["__verified_proof"], ProofToken)


def test_authorization_detail():
    cd = CredentialDefinition(type=[
        "VerifiableCredential",
        "UniversityDegreeCredential"
    ])

    ad = AuthorizationDetail(type="openid_credential",
                             format="jwt_vc_json",
                             credential_definition=cd)

    _query = quote_plus(f"[{ad.to_json()}]")
    _q = unquote_plus(_query)
    _ads = [AuthorizationDetail(**_data) for _data in json.loads(_q)]
    assert len(_ads) == 1
    ad = _ads[0]
    assert set(ad.keys()) == {'format', 'type', 'credential_definition'}
    assert ad['format'] == "jwt_vc_json"
    assert ad['type'] == "openid_credential"
    assert isinstance(ad['credential_definition'], CredentialDefinition)


def test_authorization_detail2():
    info = [
        {
            "type": "openid_credential",
            "format": "ldp_vc",
            "credential_definition": {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://www.w3.org/2018/credentials/examples/v1"
                ],
                "type": [
                    "VerifiableCredential",
                    "UniversityDegreeCredential"
                ]
            }
        },
        {
            "type": "openid_credential",
            "format": "mso_mdoc",
            "doctype": "org.iso.18013.5.1.mDL"
        }
    ]

    ads = [AuthorizationDetail(**args) for args in info]

    assert {ad['format'] for ad in ads} == {"mso_mdoc", "ldp_vc"}


def check_0(ads):
    assert len(ads) == 1
    assert {a['type'] for a in ads} == {"openid_credential"}
    assert {a['format'] for a in ads} == {"jwt_vc_json"}

    ad = ads[0]
    assert set(ad.keys()) == {"type", "format", "credential_definition"}
    assert set(ad["credential_definition"].keys()) == {"type"}
    assert ad["credential_definition"]["type"] == ['VerifiableCredential',
                                                   'UniversityDegreeCredential']


def check_1(ads):
    assert len(ads) == 1
    assert {ad['type'] for ad in ads} == {"openid_credential"}
    assert {ad['format'] for ad in ads} == {"jwt_vc_json"}

    ad = ads[0]
    assert set(ad.keys()) == {"type", "format", "credential_definition"}
    assert set(ad["credential_definition"].keys()) == {"type", "credentialSubject"}
    assert ad["credential_definition"]["type"] == ['VerifiableCredential',
                                                   'UniversityDegreeCredential']
    assert len(ad["credential_definition"]["credentialSubject"]) == 3
    assert set(ad["credential_definition"]["credentialSubject"].keys()) == {"degree",
                                                                            "family_name",
                                                                            "given_name"}


def check_2(ads):
    assert len(ads) == 1
    assert {ad['type'] for ad in ads} == {"openid_credential"}
    assert {ad['format'] for ad in ads} == {"ldp_vc"}

    ad = ads[0]
    assert set(ad.keys()) == {"type", "format", "credential_definition"}
    assert set(ad["credential_definition"].keys()) == {"type", "credentialSubject", "@context"}
    assert ad["credential_definition"]["type"] == ['VerifiableCredential',
                                                   'UniversityDegreeCredential']
    assert len(ad["credential_definition"]["credentialSubject"]) == 3
    assert set(ad["credential_definition"]["credentialSubject"].keys()) == {"degree",
                                                                            "family_name",
                                                                            "given_name"}


def check_3(ads):
    assert len(ads) == 1
    assert {ad['type'] for ad in ads} == {"openid_credential"}
    assert {ad['format'] for ad in ads} == {"mso_doc"}


def check_4(ads):
    assert len(ads) == 2
    assert {ad['type'] for ad in ads} == {"openid_credential"}
    assert {ad['format'] for ad in ads} == {'mso_mdoc', 'ldp_vc'}


def check_5(ads):
    assert len(ads) == 1
    assert {ad['type'] for ad in ads} == {"openid_credential"}
    assert {ad['format'] for ad in ads} == {"jwt_vc_json"}


@pytest.mark.parametrize(
    "filename, check",
    [
        ("authorization_details.json", check_0),
        ("authorization_details_jwt_vc_json.json", check_1),
        ("authorization_details_ldp_vc.json", check_2),
        ("authorization_details_mso_doc.json", check_3),
        ("authorization_details_multiple_credentials.json", check_4),
        ("authorization_details_with_as.json", check_5),
    ],
)
def test_authorization_detail_example(filename, check):
    info = json.loads(open(os.path.join(_dirname, "example", filename)).read())
    ads = [AuthorizationDetail(**args) for args in info]
    check(ads)


def test_credential_definition():
    _def = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "type": [
            "VerifiableCredential",
            "UniversityDegreeCredential"
        ],
        "credentialSubject": {
            "given_name": {
                "display": [
                    {
                        "name": "Given Name",
                        "locale": "en-US"
                    }
                ]
            },
            "last_name": {
                "display": [
                    {
                        "name": "Surname",
                        "locale": "en-US"
                    }
                ]
            },
            "degree": {},
            "gpa": {
                "display": [
                    {
                        "name": "GPA"
                    }
                ]
            }
        }
    }

    _cd = CredentialDefinition(**_def)
    _cd.verify()
    assert len(_cd['credentialSubject']) == 4
    _cs = _cd['credentialSubject']
    assert set(_cs.keys()) == {'given_name', 'last_name', 'degree', 'gpa'}
    # assert isinstance(_cs['given_name'], ClaimsSupport)


def test_credential_metadata_jwt_vc_json():
    _file_name = "credential_metadata_jwt_vc_json.json"
    args = json.loads(open(os.path.join(_dirname, "example", _file_name)).read())
    _metadata = CredentialMetadata(**args)
    _metadata.verify()
    assert _metadata
    assert set(_metadata.keys()) == {"format", "id", "cryptographic_suites_supported",
                                     "cryptographic_binding_methods_supported",
                                     "credential_definition", "proof_types_supported",
                                     "display"}
    assert isinstance(_metadata["credential_definition"], CredentialDefinition)
    assert len(_metadata["display"]) == 1
    assert isinstance(_metadata["display"][0], DisplayProperty)
    assert _metadata["display"][0]["name"] == "University Credential"
    _credential_definition = _metadata["credential_definition"]
    assert "VerifiableCredential" in _credential_definition["type"]
    assert set(_credential_definition["credentialSubject"].keys()) == {
        "given_name", "family_name", "degree", "gpa"
    }


# def test_credential_metadata_mso_mdoc():
#     pass

def test_credential_offer_authz_code():
    _file_name = "credential_offer_authz_code.json"
    args = json.loads(open(os.path.join(_dirname, "example", _file_name)).read())
    offer = CredentialOffer(**args)
    assert offer['credential_issuer'] == "https://credential-issuer.example.com"
    assert len(offer['credentials']) == 1  # missed one, should be two eventually
    assert len(offer['grants']) == 1
    assert set(offer['grants'].keys()) == {'authorization_code'}


def test_issuer_metadata():
    _file_name = "issuer_metadata.json"
    args = json.loads(open(os.path.join(_dirname, "example", _file_name)).read())
    metadata = CredentialIssuerMetadata(**args)
    assert set(metadata.keys()) == {'credential_configurations_supported', 'credential_issuer',
                                    'credential_endpoint'}
    assert len(metadata["credential_configurations_supported"]) == 3
    # One I can deal with
    assert len([c for c in metadata["credential_configurations_supported"] if
                c["format"] == "jwt_vc_json"]) == 1


def test_credential_issuer_metadata():
    _file_name = "credential_issuer_metadata.json"
    args = json.loads(open(os.path.join(_dirname, "example", _file_name)).read())
    metadata = CredentialIssuerMetadata(**args)
    metadata.verify()
    assert set(metadata.keys()) == {'authorization_server',
                                    'credential_endpoint',
                                    'credential_issuer',
                                    'credential_configurations_supported',
                                    'deferred_credential_endpoint'}
    assert len(metadata["credential_configurations_supported"]) == 2
    # One I can deal with
    assert len([c for c in metadata["credential_configurations_supported"] if
                c["format"] == "jwt_vc"]) == 2


def test_authorization_details():
    authz_req = {
        'authorization_details': [
            {
                'type': "openid_credential",
                "format": "vc+sd-jwt",
                "credential_definition": {
                    "type": "PersonIdentificationData"}
            }
        ],
        'response_type': 'code',
        'client_id': 'YWw5eXVhMElfNWVQZXB4ZVdBTTFxaDNEdXZDOWxNUklGaWhQUTAtNmpOaw',
        'redirect_uri':
            'https://127.0.0.1:5005/authz_cb/qoY_THoYZlRRJXth_314qanSMpn_9MFe1uGV7TF5K4M',
        'client_assertion':
            'eyJ0eXAiOiJ3YWxsZXQtYXR0ZXN0YXRpb24rand0IiwiYWxnIjoiRVMyNTYiLCJraWQiOiJNWGRxT1RoZk5URkJiVEJTZERKU04ydHJkbmh0UzFGc1RXUjZjM0JYZWxWaFNYaGFPV0phWTBGNGF3In0.eyJzdWIiOiAiWVd3NWVYVmhNRWxmTldWUVpYQjRaVmRCVFRGeGFETkVkWFpET1d4TlVrbEdhV2hRVVRBdE5tcE9hdyIsICJjbmYiOiB7Imp3ayI6IHsia3R5IjogIkVDIiwgInVzZSI6ICJzaWciLCAia2lkIjogIllXdzVlWFZoTUVsZk5XVlFaWEI0WlZkQlRURnhhRE5FZFhaRE9XeE5Va2xHYVdoUVVUQXRObXBPYXciLCAiY3J2IjogIlAtMjU2IiwgIngiOiAiTFJrMFN4Q2VQeFNZZmY0RENuRzJDcXFUMnVZODB2UUZZcDVuY0U3dzRSdyIsICJ5IjogIlM0WnpETVROWXVlVXpTYVVHdEJfb3NCUzhjNUVaaUZZSkxUdXc4RnBXVEEifX0sICJhdHRlc3RlZF9zZWN1cml0eV9jb250ZXh0IjogImh0dHBzOi8vd2FsbGV0LXByb3ZpZGVyLmV4YW1wbGUub3JnL0xvQS9iYXNpYyIsICJ0eXBlIjogIldhbGxldEluc3RhbmNlQXR0ZXN0YXRpb24iLCAiYWFsIjogImh0dHBzOi8vdHJ1c3QtbGlzdC5ldS9hYWwvaGlnaCIsICJpc3MiOiAiaHR0cHM6Ly8xMjcuMC4wLjE6NDAwMCIsICJpYXQiOiAxNzAzMTc3MzUyLCAiZXhwIjogMTcwMzE4MDk1MiwgImF1ZCI6ICJZV3c1ZVhWaE1FbGZOV1ZRWlhCNFpWZEJUVEZ4YURORWRYWkRPV3hOVWtsR2FXaFFVVEF0Tm1wT2F3IiwgImp0aSI6ICJiNDU4Yzc0NjM2OTE0OTM4YWVkM2U0NGM2ZDAwZTY1YyJ9.bHYoA0aoEDrshjBW5h-XgR_-zTRjneEJTf45bua7TAmuZS2VUcxEFbuKI1fJtkMZWrr8Xkl46uVCm_3Pwsef8Q',
        'state': 'abuPlQ2kGv4FLfyV6KgPtqCbi8g2tbcH',
        'code_challenge': 'tP0BUBkSheFNRQSPKat7877UyTuQHBZpelqGgoemAcY',
        'code_challenge_method': 'S256',
        'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-client'
                                 '-attestation'}

    areq = AuthorizationRequest(**authz_req)
    _str = areq.to_urlencoded()
    areq_after = AuthorizationRequest().from_urlencoded(_str)
    assert areq_after


def test_authorization_details2():
    _info = [{'type': 'openid_credential', 'format': 'vc+sd-jwt',
              'credential_definition': {'type': ['PersonIdentificationData']}}]

    adl = [AuthorizationDetail(**item) for item in _info]
    assert adl


def test_authz_req():
    url = "https://127.0.0.1:8080/authorization?authorization_details=%5B%27type%3Dopenid_credential%26credential_configuration_id%3DPersonIdentificationData%27%5D&response_type=code&client_id=ZEEyMi1XT1pfRVozVm4yTXFZLXJULTItMDhvalQ1TTJuYVNtMzZ5TS1lbw&redirect_uri=https%3A%2F%2F127.0.0.1%3A5005%2Fauthz_cb%2FqoY_THoYZlRRJXth_314qanSMpn_9MFe1uGV7TF5K4M&state=SAMhZfcAPE9UpGayGvzgrOjtk9EXQHLn&code_challenge=sy477aMPUlRBY-htgFg7EsrZ2Jn5MU8nD_u5PNQkrac&code_challenge_method=S256"
    part = urlparse(url)
    req = AuthorizationRequest().from_urlencoded(part.query)
    assert req
    req.verify()
    assert req

