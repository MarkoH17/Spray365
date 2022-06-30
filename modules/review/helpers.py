from modules.core.auth_error import AuthError
from modules.core.auth_result import AuthResult
from modules.core.credential import Credential


def decode_auth_result_item(obj_dict):
    if "auth_complete_success" in obj_dict:
        return AuthResult(**obj_dict)
    elif "username" in obj_dict:
        return Credential(**obj_dict)
    elif "timestamp" in obj_dict:
        return AuthError(**obj_dict)
    else:
        return None
