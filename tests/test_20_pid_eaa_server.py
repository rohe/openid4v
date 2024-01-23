import os

from fedservice.utils import make_federation_combo
BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)

CONF = {
    "entity_id": "https://127.0.0.1:5001",
    "key_config": {
        "private_path": "private/pid_fed_keys.json",
        "key_defs": [
            {
                "type": "RSA",
                "use": [
                    "sig"
                ]
            },
            {
                "type": "EC",
                "crv": "P-256",
                "use": [
                    "sig"
                ]
            }
        ],
        "public_path": "static/pid_fed_keys.json",
        "read_only": False
    },
    "httpc_params": {
        "verify": False
    },
    "authority_hints": ["https://127.0.0.1:6003"],
    "trust_anchors": {
        "https://127.0.0.1:7001": {
            "keys": [
                {"kty": "RSA", "use": "sig",
                 "kid":
                     "cGE4b3Q2ZWpLWk1TUDdiLTlkREwybVBOLTlFVjVWWlRIVG1uaklSYTBBdw",
                 "n":
                     "jvhiHm-DYFUOv3Qc_KfycsEvE5Njuc4sSQMs1HCpwztGJbRLMNr9F424T9szvPsqAGGJjsbOCnmQj2RgpDS5R5smDF7CBsNtYpsqk-OUKzUru5UrmdAVQEavDHPSEBeZrj-DMdqpKxxCncVCda8wqKhQUWw6HZL7WD9rBKFi1ZfTXMNWCYGgiyeOdc8QBexCXtyohgEUeGRZvDVAc7bsVeLfVoeIBquh7URW3Dh8vmG6Hf0Hlr34nVyOpvLiG7qBAfkM8Jg-EY_Z3IjyIDJUX9ADh7fPTcGA1iKXgxR7DY48MbvWqa6pFUFNWYx0ehRXMb20_6xWN7ZviCFP83L7kw",
                 "e": "AQAB"},
                {"kty": "EC", "use": "sig",
                 "kid": "Z0RPTmdSQkhkb2VtdmhPMlNBdm1ZUi1NdTR2eEtvS2c1bkVSTUNpVFdzOA",
                 "crv": "P-256",
                 "x": "PWFFcxsLL9TML_sKWVsywOn5FArRBysXIuvCuObxcL0",
                 "y": "UP3Tqem0ZRwuufo-9zkMawJ2pW_MJjvyFBxSWFj3r-0"}]}},
    "trust_marks": [
        "eyJhbGciOiJSUzI1NiIsImtpZCI6IlNsWlRMVkJ4UWpSbFZUUlBjVkozYlVneVJrdGZkRXRZTlZwWFlVMXNjV0ZqV0RsR2F6SlhMVW80VVEifQ.eyJpYXQiOiAxNzAwMzg3MTYzLCAiaWQiOiAiaHR0cDovL2RjNGV1LmV4YW1wbGUuY29tL1BlcnNvbklkZW50aWZpY2F0aW9uRGF0YS9zZSIsICJzdWIiOiAiaHR0cHM6Ly8xMjcuMC4wLjE6NTAwMSIsICJleHAiOiAxNzAyOTc5MTYzLCAiaXNzIjogImh0dHBzOi8vMTI3LjAuMC4xOjUwMDQifQ.c-eS3N9QSR9RCJW7VffjL7PqLFAVFTz9KJC3HPX_BxwMO9cJW123R8HVLc6BLL1B-T-hJXZrawcNHtsuFBuCp3k5dKZ6DuUxRNonRHiwMJ8SdW3qyg2Ax_u5v8M-z6y9AjX1zz30fW3NFE1TayCxWqRp06Xp1FMCrRNXfEbXzJfPNHsWFD-OEFJVfMB7avOMnvwuvtx6N0moNH2aNzi0w2pBuwcaempX8IHDqz36m-kq2RTJZIvCYVUkbMW3Df4UYrlodwgTOX2cIyjDWLPM0WZc4I6z0BZGD8Uk0G89yCoHSHIRMZwscRmne4yW1KrDoGDcdhyR2wxaMoto2un02Q"],
    "endpoints": [
        "entity_configuration"
    ],
    "entity_type": {
        "openid_credential_issuer": {
            "class": "openid4v.openid_credential_issuer.OpenidCredentialIssuer",
            "kwargs": {
                "config": {
                    "client_authn_methods": {
                        "client_secret_basic": "idpyoidc.server.client_authn.ClientSecretBasic",
                        "client_secret_post": "idpyoidc.server.client_authn.ClientSecretPost",
                        "client_assertion":
                            "openid4v.openid_credential_issuer.client_authn.ClientAssertion",
                        "dpop_client_auth": "idpyoidc.server.oauth2.add_on.dpop.DPoPClientAuth",
                        "wallet_instance_attestation":
                            "openid4v.openid_credential_issuer.client_authn"
                            ".ClientAuthenticationAttestation"
                    },
                    "keys": {
                        "key_defs": [
                            {
                                "type": "RSA",
                                "use": [
                                    "sig"
                                ]
                            },
                            {
                                "type": "EC",
                                "crv": "P-256",
                                "use": [
                                    "sig"
                                ]
                            }
                        ],
                        "private_path": "private/pid_fed_keys.json",
                        "public_path": "static/pid_fed_keys.json",
                        "read_only": False
                    },
                    "endpoint": {
                        "token": {
                            "path": "token",
                            "class": "openid4v.openid_credential_issuer.access_token.Token",
                            "kwargs": {
                                "client_authn_method": ["wallet_instance_attestation"]
                            }
                        },
                        "authorization": {
                            "path": "authorization",
                            "class":
                                "openid4v.openid_credential_issuer.authorization.Authorization",
                            "kwargs": {
                                "response_types_supported": [
                                    "code"
                                ],
                                "response_modes_supported": [
                                    "query",
                                    "form_post"
                                ],
                                "request_parameter_supported": True,
                                "request_uri_parameter_supported": True
                            }
                        },
                        "credential": {
                            "path": "credential",
                            "class": "openid4v.openid_credential_issuer.credential.Credential",
                            "kwargs": {
                                "client_authn_method": {
                                    "dpop_client_auth": {
                                        "class": "idpyoidc.server.oauth2.add_on.dpop.DPoPClientAuth"
                                    }
                                }
                            }
                        },
                        "pushed_authorization": {
                            "path": "pushed_authorization",
                            "class":
                                "idpyoidc.server.oauth2.pushed_authorization.PushedAuthorization",
                            "kwargs": {
                                "client_authn_method": {
                                    "client_assertion": {
                                        "class":
                                            "openid4v.openid_credential_issuer.client_authn.ClientAssertion"
                                    }
                                }
                            }
                        }
                    },
                    "add_ons": {
                        "pkce": {
                            "function": "idpyoidc.server.oauth2.add_on.pkce.add_support",
                            "kwargs": {
                                "code_challenge_length": 64,
                                "code_challenge_method": "S256"
                            }
                        },
                        "dpop": {
                            "function": "idpyoidc.server.oauth2.add_on.dpop.add_support",
                            "kwargs": {
                                "dpop_signing_alg_values_supported": [
                                    "ES256"
                                ]
                            }
                        }
                    },
                    "preference": {
                        "credentials_supported": [
                            {
                                "format": "vc+sd-jwt",
                                "id": "eudiw.pid.se",
                                "cryptographic_binding_methods_supported": [
                                    "jwk"
                                ],
                                "cryptographic_suites_supported": [
                                    "RS256",
                                    "RS512",
                                    "ES256",
                                    "ES512"
                                ],
                                "display": [
                                    {
                                        "name": "Swedish PID Provider Example",
                                        "locale": "en-US"
                                    }
                                ],
                                "credential_definition": {
                                    "type": [
                                        "PersonIdentificationData"
                                    ],
                                    "credentialSubject": {
                                        "given_name": {
                                            "mandatory": True,
                                            "display": [
                                                {
                                                    "name": "Current First Name",
                                                    "locale": "en-US"
                                                },
                                                {
                                                    "name": "Nome",
                                                    "locale": "it-IT"
                                                }
                                            ]
                                        },
                                        "family_name": {
                                            "mandatory": True,
                                            "display": [
                                                {
                                                    "name": "Current Family Name",
                                                    "locale": "en-US"
                                                },
                                                {
                                                    "name": "Cognome",
                                                    "locale": "it-IT"
                                                }
                                            ]
                                        },
                                        "birthdate": {
                                            "mandatory": True,
                                            "display": [
                                                {
                                                    "name": "Date of Birth",
                                                    "locale": "en-US"
                                                },
                                                {
                                                    "name": "Data di Nascita",
                                                    "locale": "it-IT"
                                                }
                                            ]
                                        },
                                        "place_of_birth": {
                                            "mandatory": True,
                                            "display": [
                                                {
                                                    "name": "Place of Birth",
                                                    "locale": "en-US"
                                                },
                                                {
                                                    "name": "Luogo di Nascita",
                                                    "locale": "it-IT"
                                                }
                                            ]
                                        },
                                        "unique_id": {
                                            "mandatory": True,
                                            "display": [
                                                {
                                                    "name": "Unique Identifier",
                                                    "locale": "en-US"
                                                },
                                                {
                                                    "name": "Identificativo univoco",
                                                    "locale": "it-IT"
                                                }
                                            ]
                                        },
                                        "tax_id_code": {
                                            "mandatory": True,
                                            "display": [
                                                {
                                                    "name": "Tax Id Number",
                                                    "locale": "en-US"
                                                },
                                                {
                                                    "name": "Codice Fiscale",
                                                    "locale": "it-IT"
                                                }
                                            ]
                                        }
                                    }
                                }
                            }
                        ],
                        "attribute_disclosure": {
                            "": [
                                "given_name",
                                "family_name",
                                "birthdate",
                                "place_of_birth",
                                "unique_id",
                                "tax_id_code"
                            ]
                        }
                    },
                    "authentication": {
                        "anon": {
                            "acr": "http://www.swamid.se/policy/assurance/al1",
                            "class": "idpyoidc.server.user_authn.user.NoAuthn",
                            "kwargs": {
                                "user": "diana"
                            }
                        }
                    },
                    "userinfo": {
                        "class": "idpyoidc.server.user_info.UserInfo",
                        "kwargs": {
                            "db_file": full_path("users.json")
                        }
                    },
                    "authz": {
                        "class": "idpyoidc.server.authz.AuthzHandling",
                        "kwargs": {
                            "grant_config": {
                                "usage_rules": {
                                    "authorization_code": {
                                        "supports_minting": [
                                            "access_token",
                                            "refresh_token",
                                            "id_token"
                                        ],
                                        "max_usage": 1
                                    },
                                    "access_token": {},
                                    "refresh_token": {
                                        "supports_minting": [
                                            "access_token",
                                            "refresh_token",
                                            "id_token"
                                        ]
                                    }
                                },
                                "expires_in": 43200
                            }
                        }
                    },
                    "session_params": {
                        "encrypter": {
                            "kwargs": {
                                "keys": {
                                    "key_defs": [
                                        {
                                            "type": "OCT",
                                            "use": [
                                                "enc"
                                            ],
                                            "kid": "password"
                                        },
                                        {
                                            "type": "OCT",
                                            "use": [
                                                "enc"
                                            ],
                                            "kid": "salt"
                                        }
                                    ]
                                },
                                "iterations": 1
                            }
                        }
                    }
                }
            }
        }
    }
}

WALLET_CONF ={
    "entity_id": "https://127.0.0.1:5005",
    "httpc_params": {
      "verify": False
    },
    "key_config": {
      "key_defs": [
        {
          "type": "RSA",
          "use": [
            "sig"
          ]
        },
        {
          "type": "EC",
          "crv": "P-256",
          "use": [
            "sig"
          ]
        }
      ]
    },
    "trust_anchors": {
        "https://127.0.0.1:7001": {
            "keys": [
                {"kty": "RSA", "use": "sig",
                 "kid":
                     "cGE4b3Q2ZWpLWk1TUDdiLTlkREwybVBOLTlFVjVWWlRIVG1uaklSYTBBdw",
                 "n":
                     "jvhiHm-DYFUOv3Qc_KfycsEvE5Njuc4sSQMs1HCpwztGJbRLMNr9F424T9szvPsqAGGJjsbOCnmQj2RgpDS5R5smDF7CBsNtYpsqk-OUKzUru5UrmdAVQEavDHPSEBeZrj-DMdqpKxxCncVCda8wqKhQUWw6HZL7WD9rBKFi1ZfTXMNWCYGgiyeOdc8QBexCXtyohgEUeGRZvDVAc7bsVeLfVoeIBquh7URW3Dh8vmG6Hf0Hlr34nVyOpvLiG7qBAfkM8Jg-EY_Z3IjyIDJUX9ADh7fPTcGA1iKXgxR7DY48MbvWqa6pFUFNWYx0ehRXMb20_6xWN7ZviCFP83L7kw",
                 "e": "AQAB"},
                {"kty": "EC", "use": "sig",
                 "kid": "Z0RPTmdSQkhkb2VtdmhPMlNBdm1ZUi1NdTR2eEtvS2c1bkVSTUNpVFdzOA",
                 "crv": "P-256",
                 "x": "PWFFcxsLL9TML_sKWVsywOn5FArRBysXIuvCuObxcL0",
                 "y": "UP3Tqem0ZRwuufo-9zkMawJ2pW_MJjvyFBxSWFj3r-0"}]}},
    "services": [
      "entity_configuration",
      "entity_statement",
      "list",
      "trust_mark_status"
    ],
    "entity_type": {
      "wallet": {
        "class": "openid4v.client.Wallet",
        "kwargs": {
          "config": {
            "services": {
              "wallet_instance_attestation": {
                "class": "openid4v.client.wallet_instance_attestation.WalletInstanceAttestation"
              }
            }
          },
          "key_conf": {
            "key_defs": [
              {
                "type": "EC",
                "crv": "P-256",
                "use": [
                  "sig"
                ]
              }
            ]
          }
        }
      },
      "pid_eaa_consumer": {
        "class": "openid4v.client.pid_eaa_consumer.PidEaaHandler",
        "kwargs": {
          "config": {
            "add_ons": {
              "pkce": {
                "function": "idpyoidc.client.oauth2.add_on.pkce.add_support",
                "kwargs": {
                  "code_challenge_length": 64,
                  "code_challenge_method": "S256"
                }
              },
              "dpop": {
                "function": "idpyoidc.client.oauth2.add_on.dpop.add_support",
                "kwargs": {
                  "dpop_signing_alg_values_supported": [
                    "ES256"
                  ]
                }
              },
              "pushed_authorization": {
                "function": "idpyoidc.client.oauth2.add_on.par.add_support",
                "kwargs": {
                  "body_format": "urlencoded",
                  "signing_algorithm": "RS256",
                  "merge_rule": "lax",
                  "authn_method": {
                    "client_assertion": {
                      "class": "openid4v.client.client_authn.ClientAssertion"
                    }
                  }
                }
              }
            },
            "preference": {
              "response_types_supported": [
                "code"
              ],
              "response_modes_supported": [
                "query",
                "form_post"
              ],
              "request_parameter_supported": True,
              "request_uri_parameter_supported": True
            },
            "services": {
              "pid_eaa_authorization": {
                "class": "openid4v.client.pid_eaa.Authorization",
                "kwargs": {
                  "client_authn_methods": {
                    "client_assertion": "openid4v.client.client_authn.ClientAssertion"
                  }
                }
              },
              "pid_eaa_token": {
                "class": "openid4v.client.pid_eaa.AccessToken",
                "kwargs": {
                  "client_authn_methods": {
                    "client_assertion": "openid4v.client.client_authn.ClientAuthenticationAttestation"
                  }
                }
              },
              "credential": {
                "path": "credential",
                "class": "openid4v.client.pid_eaa.Credential",
                "kwargs": {
                  "client_auth_methods": ["bearer_header"]
                }
              }
            }
          }
        }
      }
    }
  }

def test_create_id_token():
    server = make_federation_combo(**CONF)
    oic = server["openid_credential_issuer"]

    wallet = make_federation_combo(**WALLET_CONF)
    _handler = wallet["pid_eaa_consumer"]
    _actor = _handler.get_consumer(oic.context.entity_id)
    if _actor is None:
        _actor = _handler.new_consumer(oic.context.entity_id)

    endpoint = oic.get_endpoint("credential")
    request = {'format': 'vc+sd-jwt',
               'credential_definition': {'type': ['PersonIdentificationData']}}

    resp = endpoint.credential_constructor(user_id='diana', request=request)
    assert resp
