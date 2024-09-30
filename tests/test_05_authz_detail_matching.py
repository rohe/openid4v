from openid4v.openid_credential_issuer.credential import CredentialConstructor
from openid4v.openid_credential_issuer.credential import matching_authz_detail_against_supported

AUTHZ_DETAIL_1 = {
    "type": "openid_credential",
    "credential_configuration_id": "org.iso.18013.5.1.mDL"
}

AUTHZ_DETAIL_2 = {
    "type": "openid_credential",
    "format": "vc+sd-jwt",
    "vct": "SD_JWT_VC_example_in_OpenID4VCI"
}

AUTHZ_DETAIL_3 = {
    "type": "openid_credential",
    "credential_configuration_id": "UniversityDegreeCredential"
}

AUTHZ_DETAIL_4 = {
    "type": "openid_credential",
    "credential_configuration_id": "SD_JWT_VC_example_in_OpenID4VCI"
}

CREDENTIAL_CONFIGURATIONS_SUPPORTED_1 = {
    "SD_JWT_VC_example_in_OpenID4VCI": {
        "format": "vc+sd-jwt",
        "scope": "SD_JWT_VC_example_in_OpenID4VCI",
        "cryptographic_binding_methods_supported": [
            "jwk"
        ],
        "credential_signing_alg_values_supported": [
            "ES256"
        ],
        "display": [
            {
                "name": "IdentityCredential",
                "logo": {
                    "uri": "https://university.example.edu/public/logo.png",
                    "alt_text": "a square logo of a university"
                },
                "locale": "en-US",
                "background_color": "#12107c",
                "text_color": "#FFFFFF"
            }
        ],
        "proof_types_supported": {
            "jwt": {
                "proof_signing_alg_values_supported": [
                    "ES256"
                ]
            }
        },
        "vct": "SD_JWT_VC_example_in_OpenID4VCI",
        "claims": {
            "given_name": {
                "display": [
                    {
                        "name": "Given Name",
                        "locale": "en-US"
                    },
                ]
            }
        }
    }
}

CREDENTIAL_CONFIGURATIONS_SUPPORTED_2 = {
    "org.iso.18013.5.1.mDL": {
        "format": "mso_mdoc",
        "doctype": "org.iso.18013.5.1.mDL",
        "cryptographic_binding_methods_supported": [
            "cose_key"
        ],
        "credential_signing_alg_values_supported": [
            "ES256",
            "ES384",
            "ES512"
        ],
        "display": [
            {
                "name": "Mobile Driving License",
                "locale": "en-US",
                "logo": {
                    "uri": "https://state.example.org/public/mdl.png",
                    "alt_text": "state mobile driving license"
                },
                "background_color": "#12107c",
                "text_color": "#FFFFFF"
            }
        ],
        "claims": {
            "org.iso.18013.5.1": {
                "given_name": {
                    "display": [
                        {
                            "name": "Given Name",
                            "locale": "en-US"
                        },
                    ]
                },
                "family_name": {
                    "display": [
                        {
                            "name": "Surname",
                            "locale": "en-US"
                        }
                    ]
                }
            }
        }
    }
}


def test_match_1_1():
    m = matching_authz_detail_against_supported(AUTHZ_DETAIL_1, CREDENTIAL_CONFIGURATIONS_SUPPORTED_1)
    assert m == []


def test_match_1_2():
    m = matching_authz_detail_against_supported(AUTHZ_DETAIL_1, CREDENTIAL_CONFIGURATIONS_SUPPORTED_2)
    assert len(m) == 1


def test_match_2_1():
    m = matching_authz_detail_against_supported(AUTHZ_DETAIL_2, CREDENTIAL_CONFIGURATIONS_SUPPORTED_1)
    assert len(m) == 1


def test_match_2_2():
    m = matching_authz_detail_against_supported(AUTHZ_DETAIL_2, CREDENTIAL_CONFIGURATIONS_SUPPORTED_2)
    assert m == []


def test_match_3_1():
    m = matching_authz_detail_against_supported(AUTHZ_DETAIL_3, CREDENTIAL_CONFIGURATIONS_SUPPORTED_1)
    assert m == []


def test_match_3_2():
    m = matching_authz_detail_against_supported(AUTHZ_DETAIL_3, CREDENTIAL_CONFIGURATIONS_SUPPORTED_2)
    assert m == []


def test_match_4_1():
    m = matching_authz_detail_against_supported(AUTHZ_DETAIL_4, CREDENTIAL_CONFIGURATIONS_SUPPORTED_1)
    assert len(m) == 1


def test_match_4_2():
    m = matching_authz_detail_against_supported(AUTHZ_DETAIL_4, CREDENTIAL_CONFIGURATIONS_SUPPORTED_2)
    assert m == []


def test_demo():
    authz_details = {'type': 'openid_credential', 'format': 'vc+sd-jwt', 'vct': 'PersonIdentificationData'}
    credential_configurations_supported = {
        'PersonIdentificationData': {
            'format': 'vc+sd-jwt', 'id': 'eudiw.pid.se',
            'cryptographic_binding_methods_supported': [
                'jwk'],
            'cryptographic_suites_supported': ['RS256',
                                               'RS512',
                                               'ES256',
                                               'ES512'],
            'display': {
                'name': 'Swedish PID Provider Example',
                'locale': 'en-US'},
            'vct': 'PersonIdentificationData',
            'credential_definition': {
                'type': ['PersonIdentificationData'],
                'credentialSubject': {'name': {'display': [
                    {'name': 'Name of a person',
                     'locale': 'en-US'}],
                    'mandatory': True},
                    'family_name': {
                        'display': [{
                            'locale': 'en-US',
                            'name': 'Current Family Name'}],
                        'mandatory': True},
                    'given_name': {
                        'display': [{
                            'locale': 'en-US',
                            'name': 'Current First Name'}],
                        'mandatory': True},
                    'email': {'display': [
                        {
                            'locale': 'en-US',
                            'name': 'Current email address'}],
                        'mandatory': True},
                    'nickname': {
                        'mandatory': True,
                        'display': [{
                            'name': 'A persons nickname',
                            'locale': 'en-US'}]}}}}}
    cc = CredentialConstructor(None)
    m = matching_authz_detail_against_supported(authz_details, credential_configurations_supported)
    assert len(m) == 1
