from modules.core.auth_error import AuthError
from modules.core.credential import Credential


class AuthResult:
    def __init__(
        self,
        credential: Credential,
        auth_complete_success=False,
        auth_partial_success=False,
        auth_error: AuthError = None,
        auth_token=None,
    ):
        self.credential = credential
        self.auth_complete_success = auth_complete_success
        self.auth_partial_success = auth_partial_success
        self.auth_error = auth_error
        self.auth_token = auth_token
