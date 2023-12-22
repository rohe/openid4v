from idpyoidc.server.session.manager import SessionManager
from idpyoidc.server.token.handler import TokenHandler

dump = {
    'db': {
        '8f0d060e983cca2d98510b179844cb99ca63b66d99304a96303d2480eeecaf7f;;Sm1fSnpCNUxhY0F4X0FQOEt2dXhFa2xSb0g5VW5YRG5ZS1cxR0o2MjNzWQ': [
            'idpyoidc.server.session.info.ClientSessionInfo',
            {
                'subordinate': [
                    '8f0d060e983cca2d98510b179844cb99ca63b66d99304a96303d2480eeecaf7f;;Sm1fSnpCNUxhY0F4X0FQOEt2dXhFa2xSb0g5VW5YRG5ZS1cxR0o2MjNzWQ;;1554215ea03611ee862fc6e53279847c'
                ],
                'revoked': False,
                'type': 'ClientSessionInfo',
                'extra_args': {},
                'id': 'Sm1fSnpCNUxhY0F4X0FQOEt2dXhFa2xSb0g5VW5YRG5ZS1cxR0o2MjNzWQ'
            }
        ],
        '8f0d060e983cca2d98510b179844cb99ca63b66d99304a96303d2480eeecaf7f': [
            'idpyoidc.server.session.info.UserSessionInfo',
            {
                'subordinate': [
                    '8f0d060e983cca2d98510b179844cb99ca63b66d99304a96303d2480eeecaf7f;;Sm1fSnpCNUxhY0F4X0FQOEt2dXhFa2xSb0g5VW5YRG5ZS1cxR0o2MjNzWQ'
                ],
                'revoked': False,
                'type': 'UserSessionInfo',
                'extra_args': {},
                'id': '8f0d060e983cca2d98510b179844cb99ca63b66d99304a96303d2480eeecaf7f'
            }
        ],
        '8f0d060e983cca2d98510b179844cb99ca63b66d99304a96303d2480eeecaf7f;;Sm1fSnpCNUxhY0F4X0FQOEt2dXhFa2xSb0g5VW5YRG5ZS1cxR0o2MjNzWQ;;1554215ea03611ee862fc6e53279847c': [
            'idpyoidc.server.session.grant.Grant',
            {
                'expires_at': 1705778464,
                'issued_at': 1703186464,
                'not_before': 0,
                'revoked': False,
                'usage_rules': {
                    'authorization_code': {
                        'supports_minting': [
                            'access_token',
                            'refresh_token'
                        ],
                        'max_usage': 1,
                        'expires_in': 120
                    },
                    'access_token': {
                        'expires_in': 3600
                    },
                    'refresh_token': {
                        'supports_minting': [
                            'access_token',
                            'refresh_token'
                        ],
                        'expires_in': 86400
                    }
                },
                'used': 1,
                'authentication_event': {
                    'idpyoidc.server.authn_event.AuthnEvent': {
                        'uid': '8f0d060e983cca2d98510b179844cb99ca63b66d99304a96303d2480eeecaf7f',
                        'authn_info': 'urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword',
                        'authn_time': 1703186464,
                        'valid_until': 1703190064
                    }
                },
                'authorization_request': {
                    'openid4v.message.AuthorizationRequest': {
                        'authorization_details': [
                            {
                                'type': 'openid_credential',
                                "format": "vc+sd-jwt",
                                "credential_definition": {
                                    "type": 'PersonIdentificationData'
                                }
                            }
                        ],
                        'response_type': 'code',
                        'client_id': 'Sm1fSnpCNUxhY0F4X0FQOEt2dXhFa2xSb0g5VW5YRG5ZS1cxR0o2MjNzWQ',
                        'redirect_uri': 'https://127.0.0.1:5005/authz_cb/qoY_THoYZlRRJXth_314qanSMpn_9MFe1uGV7TF5K4M',
                        'client_assertion': 'eyJ0eXAiOiJ3YWxsZXQtYXR0ZXN0YXRpb24rand0IiwiYWxnIjoiRVMyNTYiLCJraWQiOiJNWGRxT1RoZk5URkJiVEJTZERKU04ydHJkbmh0UzFGc1RXUjZjM0JYZWxWaFNYaGFPV0phWTBGNGF3In0.eyJzdWIiOiAiU20xZlNucENOVXhoWTBGNFgwRlFPRXQyZFhoRmEyeFNiMGc1Vlc1WVJHNVpTMWN4UjBvMk1qTnpXUSIsICJjbmYiOiB7Imp3ayI6IHsia3R5IjogIkVDIiwgInVzZSI6ICJzaWciLCAia2lkIjogIlNtMWZTbnBDTlV4aFkwRjRYMEZRT0V0MmRYaEZhMnhTYjBnNVZXNVlSRzVaUzFjeFIwbzJNak56V1EiLCAiY3J2IjogIlAtMjU2IiwgIngiOiAiVk1nNkpVdTRKczQzZ0Q0bXNiSzRKT2dmbmFrNy1ZNTVQSVpKeVZ4SzIyNCIsICJ5IjogIjg2MUItZzJna21WcnpUeUpwZTAtRFBUNVQwSGhZMVlIQ3ZqZE5WU2xfcUEifX0sICJhdHRlc3RlZF9zZWN1cml0eV9jb250ZXh0IjogImh0dHBzOi8vd2FsbGV0LXByb3ZpZGVyLmV4YW1wbGUub3JnL0xvQS9iYXNpYyIsICJ0eXBlIjogIldhbGxldEluc3RhbmNlQXR0ZXN0YXRpb24iLCAiYWFsIjogImh0dHBzOi8vdHJ1c3QtbGlzdC5ldS9hYWwvaGlnaCIsICJpc3MiOiAiaHR0cHM6Ly8xMjcuMC4wLjE6NDAwMCIsICJpYXQiOiAxNzAzMTg2NDUzLCAiZXhwIjogMTcwMzE5MDA1MywgImF1ZCI6ICJTbTFmU25wQ05VeGhZMEY0WDBGUU9FdDJkWGhGYTJ4U2IwZzVWVzVZUkc1WlMxY3hSMG8yTWpOeldRIiwgImp0aSI6ICJiMjRkOTBiZGE0NDk0ODhmYmU4MjY5ZTY5MDY5MjBkNSJ9.DlyeITQ-N7WapVZqnjoFc7YIXSNY0DskWjtXppAM9vNt5L-bO-4vtZihuDGdZJzSvwkAJEiIHLoZ9WytUKqGZw',
                        'state': '7MxEbOqebtgJJFLYuwq89zzCj1Hq0d0i',
                        'code_challenge': 'EM0LdX5m0f_owO-qQFIW0wSNlv7Da2-27JeycFd9K5E',
                        'code_challenge_method': 'S256',
                        'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation',
                        'authenticated': True
                    }
                },
                'claims': {
                    'introspection': {},
                    'access_token': {}
                },
                'extra': {},
                'resources': [
                    'Sm1fSnpCNUxhY0F4X0FQOEt2dXhFa2xSb0g5VW5YRG5ZS1cxR0o2MjNzWQ'
                ],
                'scope': [],
                'sub': 'fe17ade8a0f5994c7ed30ada0b39a2ba0bca7ca1f21a157272effc7ebceb9c69',
                'issued_token': [
                    {
                        'idpyoidc.server.session.token.AuthorizationCode': {
                            'expires_at': 1703186584,
                            'issued_at': 1703186464,
                            'not_before': 0,
                            'revoked': False,
                            'usage_rules': {
                                'supports_minting': [
                                    'access_token',
                                    'refresh_token'
                                ],
                                'max_usage': 1,
                                'expires_in': 120
                            },
                            'used': 0,
                            'claims': {},
                            'id': '15545228a03611ee862fc6e53279847c',
                            'name': 'AuthorizationCode',
                            'resources': [],
                            'scope': [],
                            'token_class': 'authorization_code',
                            'value': 'Z0FBQUFBQmxoSkFnby1rRHVMWWVqNk8xUzhGaHdXcnZkNjRLMmk1QjAxLUFOV0RFZHlCUVBOMDVlTmFMQkJhMTRSTVQ3TWVvZkxfNDBveXlONEc3QmRjUDRtdm9sNk9ld216dUo4YlVRLVVFdllIcTVIVUtmTnFoR09Nc3VWYkZQa20zR0NWWm5zVEtsOWhINnpwRG8wRjlHYkpmTmhweWE3di1KdlBBb3p0QmRYcWxVRkhZakpZWDhEa1Q5M1NHc1dQRVFBSlZzSkFVdnpOcHdvUm51MjhPeXhLczBFOUVWQndOUXk4X2EtSUMwMXpES0staDRHNFRtNnEyNktLVnYyREJwMGZTZElkZmI0Sl8wOXkzUGREUTlDMkN0S1hPWXZnVnZ1bHlZTFYtQjdMOFhuMlJRMVJBYmVBNWpUd01yUW1MRjZPMEgxMEw1ekpRcTZOa21DdF9icVZmQzl6NUQtQmhMY1c0Y2wtN21ZMHVyalFsZlM4QUhHZzA2Smpjd1pjQ2o2NHdObXRUVkZWclI0d20yWTRsc2w4RGdqSG1GT3V5ck5BRkJyMi1JRHFPUk5TWEdBT29NTXRXRFR3dE5kcUoyRm5vZFU4NWRJckZCV011bTdOTVJvNVZRNmFlS2lVT1pjamxXcWlfODc5OWdzLVgyS3NNa0lMbFVFT0cySmpBUXlyV21lTXFkajhTRlkwVXRRcHFEeEs5Nk80X20zVGxZRThaUnBuNWRYaW84SHd0d0h2YmtvY3JfTU51bXZ6czRYQWVhZkpzRDdDZWtpUl9FSkprR2tMWDlIbWRVVDRtcXZpN0dnWXpCMC0zR3Vxc1dhYTBwbEhqZXZZTWZiZGdwOVA5ZEVnSjAtSDJrUHlILWVnb3dTNDQwVGk0aDlkazhJM1psbjhKX0J6Wk1IeTN5T3ZpYUQ1UlZWYzZHWm5FNjl0dmNJNDVLc0ZLVmhTc3dMamhNUmRVUlpabU5nS2tiem95UUJYazNnd0Q1SmZVZ1lVVnM1X1BBQjBTWk96cVYzdWpDS1VDQ2E3UWE3c2VjcUswemEzOUprVGV3YU1YSnVrLXBRSkxsTF9fQjZadm5MdzZCRmY3aUwxRnVLRVBZc0dNbW5Eb2lmMi03dU51dU1Va0wxajJ3YVdjOHQtTm4ySnhqeV9Fam4zZ0lqTlI2VEU9'
                        }
                    }
                ],
                'token_map': {
                    'authorization_code': 'idpyoidc.server.session.token.AuthorizationCode',
                    'access_token': 'idpyoidc.server.session.token.AccessToken',
                    'refresh_token': 'idpyoidc.server.session.token.RefreshToken',
                    'id_token': 'idpyoidc.server.session.token.IDToken'
                }
            }
        ]
    },
    'crypt_config': {
        'class': 'cryptojwt.jwe.fernet.FernetEncrypter',
        'kwargs': {
            'password': 'BYTES:7ZJwddsdYFKJ/5KEzBlSIHOqpZW1t741',
            'salt': 'BYTES:uJ91O1ry7Gohhkp4R4OVTEMvdrsn3B9m',
            'iterations': 1
        }
    }
}


def test_session_manager_load():
    sman = SessionManager(handler=TokenHandler(), conf={"password": "hola!"})
    sman.load(dump)
    assert sman
