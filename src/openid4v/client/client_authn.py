from idpyoidc.client.client_auth import ClientAuthnMethod

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation"


class ClientAssertion(ClientAuthnMethod):

    def construct(self, request, service=None, http_args=None, **kwargs):
        request["client_assertion"] = kwargs["wallet_instance_attestation"]
        request["client_assertion_type"] = ASSERTION_TYPE
        return {}
