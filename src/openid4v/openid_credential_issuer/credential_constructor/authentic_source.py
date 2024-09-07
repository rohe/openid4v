import json
import logging
from typing import Optional
from typing import Union

from idpyoidc.message import Message

logger = logging.getLogger(__name__)


class CredentialConstructor(object):

    def __init__(self, upstream_get, config: dict, **kwargs):
        self.upstream_get = upstream_get
        self.config = config

    def get_response(
            self,
            url: str,
            method: Optional[str] = "POST",
            body: Optional[dict] = None,
            headers: Optional[dict] = None,
            **kwargs
    ):
        """

        :param url:
        :param method:
        :param body:
        :param response_body_type:
        :param headers:
        :param kwargs:
        :return:
        """
        httpc = self.upstream_get('attribute', 'httpc')
        httpc_params = self.upstream_get("attribute", "httpc_params")
        try:
            resp = httpc(method, url, data=body, headers=headers, **httpc_params)
        except Exception as err:
            logger.error(f"Exception on request: {err}")
            raise

        if 300 <= resp.status_code < 400:
            return {"http_response": resp}

        if resp.status_code == 200:
            return resp.text

    def __call__(self,
                 user_id: str,
                 client_id: str,
                 request: Union[dict, Message],
                 grant: Optional[dict] = None,
                 id_token: Optional[str] = None
                 ) -> str:
        logger.debug(":" * 20 + f"Credential constructor[authentic_source]" + ":" * 20)

        body = {
            "authentic_source": "sunet2",
            "document_type": "PDA1",
            "document_id": "document_id_7"
        }

        msg = self.get_response(url="http://vc-interop-1.sunet.se/api/v1/credential",
                                body=body,
                                headers={'Content-Type': 'application/json'})
        return msg
