import json
import os
from urllib.parse import quote_plus
from urllib.parse import unquote_plus

import pytest
from cryptojwt import JWT
from cryptojwt.jwt import utc_time_sans_frac
from cryptojwt.key_jar import build_keyjar
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS

from oidc4vci.message import AuthorizationDetail
from oidc4vci.message import ClaimsSupport
from oidc4vci.message import CredentialDefinition
from oidc4vci.message import CredentialIssuerMetadata
from oidc4vci.message import CredentialMetadata
from oidc4vci.message import CredentialOffer
from oidc4vci.message import CredentialRequestJwtVcJson
from oidc4vci.message import DisplayProperty

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
    _jwt = JWT(key_jar=KEYJAR, sign_alg='ES256', iss=JWT_ISSUER)
    _jws = _jwt.pack(payload, jws_headers={"typ": "openid4vci-proof+jwt"})

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
    assert cr


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
    assert isinstance(_cs['given_name'], ClaimsSupport)


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
    assert set(metadata.keys()) == {'credentials_supported', 'credential_issuer',
                                    'credential_endpoint'}
    assert len(metadata["credentials_supported"]) == 3
    # One I can deal with
    assert len([c for c in metadata["credentials_supported"] if c["format"] == "jwt_vc_json"]) == 1


def test_credential_issuer_metadata():
    _file_name = "credential_issuer_metadata.json"
    args = json.loads(open(os.path.join(_dirname, "example", _file_name)).read())
    metadata = CredentialIssuerMetadata(**args)
    metadata.verify()
    assert set(metadata.keys()) == {'authorization_server',
                                    'credential_endpoint',
                                    'credential_issuer',
                                    'credentials_supported',
                                    'deferred_credential_endpoint'}
    assert len(metadata["credentials_supported"]) == 2
    # One I can deal with
    assert len([c for c in metadata["credentials_supported"] if c["format"] == "jwt_vc"]) == 2
