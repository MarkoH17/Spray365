from __future__ import annotations
import datetime
import json
from modules.core.auth_error import AuthError
from modules.core.credential import Credential
from modules.core.auth_result import AuthResult
from modules.core.output import console
from modules.core import constants
from msal import PublicClientApplication
import warnings

warnings.filterwarnings("ignore")


def decode_execution_plan_item(credential_dict):
    return Credential(**credential_dict)


def authenticate_credential(
    credential: Credential, proxy: str, insecure: bool = False
) -> AuthResult:
    proxies = None
    if proxy:
        proxies = {
            "http": proxy,
            "https": proxy,
        }
    if insecure:
        auth_app = PublicClientApplication(
            credential.client_id[1],
            authority="https://login.microsoftonline.com/organizations",
            proxies=proxies,
            verify=False,
        )
    else:
        auth_app = PublicClientApplication(
            credential.client_id[1],
            authority="https://login.microsoftonline.com/organizations",
            proxies=proxies,
        )

    if credential.user_agent:
        # TODO: Find official way to influence user-agent in future versions of msal
        auth_app.authority._http_client._http_client.headers[
            "User-Agent"
        ] = credential.user_agent[1]

    scope = "%s/.default" % credential.endpoint[1]
    raw_result = auth_app.acquire_token_by_username_password(
        username=credential.email_address, password=credential.password, scopes=[scope]
    )

    auth_result = process_raw_auth_result(credential, raw_result)
    return auth_result


def process_raw_auth_result(
    credential: Credential, raw_result: dict[str]
) -> AuthResult:
    auth_complete_success = False
    auth_partial_success = False
    auth_error: AuthError = None
    auth_token: str = None

    if "error_codes" in raw_result:
        if any(
            error_code in raw_result["error_codes"]
            for error_code in constants.auth_complete_success_error_codes
        ):
            auth_complete_success = True
            raw_result.pop("error")  # remove the error
        elif any(
            error_code in raw_result["error_codes"]
            for error_code in constants.auth_partial_success_error_codes
        ):
            auth_partial_success = True
        auth_error = get_auth_error(raw_result)
    else:
        auth_complete_success = True
        auth_token = raw_result

    return AuthResult(
        credential, auth_complete_success, auth_partial_success, auth_error, auth_token
    )


def get_auth_error(raw_auth_result: dict[str]) -> AuthError:
    error_codes: dict[int] = raw_auth_result["error_codes"]
    error_code = error_codes[0]

    message = None

    timestamp = raw_auth_result["timestamp"] if "timestamp" in raw_auth_result else None
    trace_id = raw_auth_result["trace_id"] if "trace_id" in raw_auth_result else None
    correlation_id = (
        raw_auth_result["correlation_id"]
        if "correlation_id" in raw_auth_result
        else None
    )
    raw_error_message = (
        raw_auth_result["error_description"]
        if "error_description" in raw_auth_result
        else None
    )

    if error_code == 50034:
        message = "User not found"
    elif error_code == 50053:
        message = "Account locked"
    elif error_code == 50055:
        message = "Account password expired"
    elif error_code == 50057:
        message = "Account disabled"
    elif error_code == 50158:
        message = "External validation failed (is there a conditional access policy?)"
    elif error_code == 50076:
        message = "Multi-Factor Authentication Required"
    elif error_code == 50126:
        message = "Invalid credentials"
    elif error_code == 53003:
        message = "Conditional access policy prevented access"
    else:
        message = "An unknown error occurred"

    return AuthError(
        timestamp, trace_id, correlation_id, message, error_code, raw_error_message
    )


def export_auth_results(auth_results: list[AuthResult]):
    export_file = "spray365_results_%s.json" % datetime.datetime.now().strftime(
        "%Y-%m-%d_%H-%M-%S"
    )

    json_execution_plan = json.dumps(auth_results, default=lambda o: o.__dict__)

    with open(export_file, "w") as execution_plan_file:
        execution_plan_file.write(json_execution_plan)

    console.print_info("Authentication results saved to file '%s'" % export_file)
