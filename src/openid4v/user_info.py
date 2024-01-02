from typing import Optional

from idpyoidc.server import user_info


class UserInfo(user_info.UserInfo):

    def load(self, info: Optional[dict] = None):
        if info:
            self.db.update(info)
