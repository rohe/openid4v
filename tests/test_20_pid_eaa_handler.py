from fedservice.build_entity import FederationEntityBuilder
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.client.oauth2 import Client

from oidc4vci.client.pid_eaa_consumer import PidEaaHandler
from oidc4vci.client.wallet_instance_attestation import WalletInstanceAttestation
from oidc4vci.client.client_authn import ClientAssertion


def test_create():
    config = {
        'entity_id': 'https://rp.example.org',
        "federation_entity": {
            'key_conf': {'key_defs': [{'type': 'RSA', 'use': ['sig']},
                                      {'type': 'EC', 'crv': 'P-256', 'use': ['sig']}]},
            'preference': {'organization_name': 'The RP',
                           'homepage_uri': 'https://rp.example.com',
                           'contacts': 'operations@rp.example.com'},
            'authority_hints': ['https://im1.example.org'],
            'client': {
                'class': 'fedservice.entity.client.FederationClientEntity',
                'kwargs': {
                    'services': {
                        'entity_configuration': {
                            'class': 'fedservice.entity.client.entity_configuration.EntityConfiguration',
                            'kwargs': {}},
                        'entity_statement': {
                            'class': 'fedservice.entity.client.entity_statement.EntityStatement',
                            'kwargs': {}},
                        'trust_mark_status': {
                            'class': 'fedservice.entity.client.trust_mark_status.TrustMarkStatus',
                            'kwargs': {}},
                        'resolve': {
                            'class': 'fedservice.entity.client.resolve.Resolve',
                            'kwargs': {}},
                        'list': {
                            'class': 'fedservice.entity.client.list.List',
                            'kwargs': {}
                        }
                    }
                }
            },
            'function': {
                'class': 'idpyoidc.node.Collection',
                'kwargs': {
                    'functions': {'trust_chain_collector': {
                        'class': 'fedservice.entity.function.trust_chain_collector.TrustChainCollector',
                        'kwargs': {
                            'trust_anchors': {},
                            'allowed_delta': 600}},
                        'verifier': {
                            'class': 'fedservice.entity.function.verifier.TrustChainVerifier',
                            'kwargs': {}},
                        'policy': {
                            'class': 'fedservice.entity.function.policy.TrustChainPolicy',
                            'kwargs': {}},
                        'trust_mark_verifier': {
                            'class': 'fedservice.entity.function.trust_mark_verifier.TrustMarkVerifier',
                            'kwargs': {}}
                    }
                }
            }
        },
        "wallet": {
            'class': Client,
            'kwargs': {
                'config': {
                    "key_conf": {"key_defs": DEFAULT_KEY_DEFS},
                    "services": {
                        "wallet_instance_attestation": {
                            "class": WalletInstanceAttestation,
                            "kwargs": {}
                        }
                    },
                    "wallet_provider_id": "https://wp.example.com"
                }
            }
        },
        "pid_eaa_consumer": {
            'class': Client,
            'kwargs': {
                'config': {
                    "key_conf": {"key_defs": DEFAULT_KEY_DEFS},
                    "base_url": "",
                    "add_ons": {
                        "pkce": {
                            "function": "idpyoidc.client.oauth2.add_on.pkce.add_support",
                            "kwargs": {"code_challenge_length": 64,
                                       "code_challenge_method": "S256"},
                        },
                        "dpop": {
                            "function": "idpyoidc.client.oauth2.add_on.dpop.add_support",
                            "kwargs": {
                                'dpop_signing_alg_values_supported': ["ES256"]
                            }
                        },
                        "pushed_authorization": {
                            "function": "idpyoidc.client.oauth2.add_on.par.add_support",
                            "kwargs": {
                                "body_format": "jws",
                                "signing_algorithm": "RS256",
                                "http_client": None,
                                "merge_rule": "lax",
                            },
                        }
                    },
                    "services": {
                        "pid_eaa_authorization": {
                            "class": "oidc4vci.client.pid_eaa.Authorization",
                            "kwargs": {
                                "response_types_supported": ["code"],
                                "response_modes_supported": ["query", "form_post"],
                                "request_parameter_supported": True,
                                "request_uri_parameter_supported": True,
                                "client_authn_methods": {"client_assertion": ClientAssertion}
                            },
                        },
                        "pid_eaa_token": {
                            "class": "oidc4vci.client.pid_eaa.AccessToken",
                            "kwargs": {}
                        }
                        # "credential": {
                        #     "path": "credential",
                        #     "class": Credential,
                        #     "kwargs": {
                        #     },
                        # }
                    }
                }
            }
        }
    }

    handler = PidEaaHandler(config=config)
    assert handler

    handler.new_consumer("https://wp.example.org")
    assert handler.get_consumer("https://wp.example.org")

def test_create_2():
    FE = FederationEntityBuilder(
        preference={
            "organization_name": "The RP",
            "homepage_uri": "https://rp.example.com",
            "contacts": "operations@rp.example.com"
        },
        key_conf={"key_defs": DEFAULT_KEY_DEFS}
    )
    FE.add_services()
    FE.add_functions()

    config = {
        "federation_entity": FE.conf,
        "wallet": {
            'class': Client,
            'kwargs': {
                'config': {
                    "key_conf": {"key_defs": DEFAULT_KEY_DEFS},
                    "services": {
                        "wallet_instance_attestation": {
                            "class": WalletInstanceAttestation,
                            "kwargs": {}
                        }
                    },
                    "wallet_provider_id": "https://wp.example.com"
                }
            }
        },
        "pid_eaa_consumer": {
            'class': Client,
            'kwargs': {
                'config': {
                    "key_conf": {"key_defs": DEFAULT_KEY_DEFS},
                    "base_url": "",
                    "add_ons": {
                        "pkce": {
                            "function": "idpyoidc.client.oauth2.add_on.pkce.add_support",
                            "kwargs": {"code_challenge_length": 64,
                                       "code_challenge_method": "S256"},
                        },
                        "dpop": {
                            "function": "idpyoidc.client.oauth2.add_on.dpop.add_support",
                            "kwargs": {
                                'dpop_signing_alg_values_supported': ["ES256"]
                            }
                        },
                        "pushed_authorization": {
                            "function": "idpyoidc.client.oauth2.add_on.par.add_support",
                            "kwargs": {
                                "body_format": "jws",
                                "signing_algorithm": "RS256",
                                "http_client": None,
                                "merge_rule": "lax",
                            },
                        }
                    },
                    "services": {
                        "pid_eaa_authorization": {
                            "class": "oidc4vci.client.pid_eaa.Authorization",
                            "kwargs": {
                                "response_types_supported": ["code"],
                                "response_modes_supported": ["query", "form_post"],
                                "request_parameter_supported": True,
                                "request_uri_parameter_supported": True,
                                "client_authn_methods": {"client_assertion": ClientAssertion}
                            },
                        },
                        "pid_eaa_token": {
                            "class": "oidc4vci.client.pid_eaa.AccessToken",
                            "kwargs": {}
                        }
                        # "credential": {
                        #     "path": "credential",
                        #     "class": Credential,
                        #     "kwargs": {
                        #     },
                        # }
                    }
                }
            }
        }
    }

    handler = PidEaaHandler(config=config)
    assert handler

    handler.new_consumer("https://wp.example.org")
    assert handler.get_consumer("https://wp.example.org")
