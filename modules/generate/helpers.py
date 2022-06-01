from __future__ import annotations
import itertools
from pathlib import Path
import random
from typing import Callable
import typing
import click
from modules.core.credential import Credential
from modules.generate.configuration import Configuration
from modules.core.output import console


def check_if_execution_plan_exists(conf: Configuration):
    if Path(conf.execution_plan.name).exists():
        console.print_error(
            "Unable to overwrite existing file '%s' with execution plan"
            % conf.execution_plan.name
        )


def get_users_and_passwords(conf: Configuration) -> tuple[list[str], list[str]]:
    user_list: list[str] = []
    password_list: list[str] = []
    for line_idx, line in enumerate(conf.user_file):
        line = line.rstrip()
        line_data = line.split(":", maxsplit=1)

        if len(line_data) != 2:
            raise click.BadParameter(
                "Invalid user:pass combo in user_file: '%s' on line %d"
                % (line, line_idx + 1)
            )

        user_list.append(line_data[0])
        password_list.append(line_data[1])
    return (user_list, password_list)


def get_passwords(conf: Configuration) -> list[str]:
    password_list: list[str] = []
    if conf.password_file:
        for line in conf.password_file:
            line = line.rstrip()
            password_list.append(line)
    elif conf.password:
        password_list.append(conf.password)

    return password_list


def get_users(conf: Configuration) -> list[str]:
    user_list: list[str] = []
    for line in conf.user_file:
        line = line.rstrip()
        user_list.append(line)
    return user_list


def get_custom_aad_values(prefix: str, input_values: list[str]) -> dict[str, str]:
    result = {}
    for i in range(len(input_values)):
        result["%s%d" % (prefix, i + 1)] = input_values[i]
    return result


def get_credentials_dict_by_key(
    credentials_list: list[Credential], grouping_func
) -> dict[str, list[Credential]]:
    sorted_combinations = sorted(credentials_list, key=grouping_func)

    grouped_combinations = {}
    for key, value in itertools.groupby(sorted_combinations, grouping_func):
        grouped_combinations[key] = list(value)
    return grouped_combinations


def _insert_random_initial_delays(
    credentials: dict[str, list[Credential]], min_delay
) -> None:
    for spray_group in list(credentials.keys())[1:]:
        for cred_idx, cred in enumerate(credentials[spray_group]):
            previous_cred_vals = next(
                (
                    (c_idx, c)
                    for c_idx, c in enumerate(credentials[spray_group - 1])
                    if c.username == cred.username
                ),
                None,
            )
            previous_cred_idx = previous_cred_vals[0]

            previous_group_delays = sum(
                [
                    c.delay + c.initial_delay
                    for c in credentials[spray_group - 1][previous_cred_idx:]
                ]
            )
            current_group_delays = sum(
                [c.delay + c.initial_delay for c in credentials[spray_group][:cred_idx]]
            )
            prior_delays = previous_group_delays + current_group_delays

            if prior_delays < min_delay:
                additional_needed_delay = min_delay - prior_delays
                cred.initial_delay = additional_needed_delay


# TODO: Replace typing.Union below with modern Union added in PEP 604 (Python 3.10+)
def get_spray_runtime(
    credentials: typing.Union[
        typing.List[Credential], typing.Dict[int, list[Credential]]
    ]
) -> int:
    runtime = 0
    if type(credentials) is dict:
        for (idx, credentials) in credentials.items():
            runtime += get_spray_runtime(credentials)
        return runtime
    elif type(credentials) is list:
        runtime = sum(
            [credential.delay + credential.initial_delay for credential in credentials]
        )
    return runtime


def get_credentials(
    conf: Configuration,
    users: list[str],
    passwords: list[str],
    aad_clients: dict[str, str],
    aad_endpoints: dict[str, str],
    user_agents: dict[str, str],
    user_and_password_pairs: bool = False,
) -> list[Credential]:
    if any("@" in username or "\\" in username for username in users):
        console.print_error(
            "Username encountered in a format like a UPN (user@domain.com) or samAccountName (domain.com\\user). Expected just username."
        )

    unique_users = list(dict.fromkeys(users))

    if user_and_password_pairs:
        if len(users) != len(passwords):
            console.print_error(
                "Unable to generate credentials from different sized lists"
            )
        source_data = zip(unique_users, passwords)
    else:
        source_data = itertools.product(unique_users, passwords)

    results = []
    client_id_values = list(aad_clients.items())
    endpoint_id_values = list(aad_endpoints.items())
    user_agent_values = list(user_agents.items())

    for (username, password) in source_data:
        username = username.strip()
        results.append(
            Credential(
                conf.domain,
                username,
                password,
                random.choice(client_id_values),
                random.choice(endpoint_id_values),
                random.choice(user_agent_values),
                conf.delay,
            )
        )

    return results


def get_credential_products(
    conf: Configuration,
    users: list[str],
    passwords: list[str],
    aad_clients: dict[str, str],
    aad_endpoints: dict[str, str],
    user_agents: dict[str, str],
    user_and_password_pairs: bool = False,
) -> list[Credential]:
    if any("@" in username or "\\" in username for username in users):
        console.print_error(
            "Username encountered in a format like a UPN (user@domain.com) or samAccountName (domain.com\\user). Expected just username."
        )

    unique_users = list(dict.fromkeys(users))

    if user_and_password_pairs:
        if len(users) != len(passwords):
            console.print_error(
                "Unable to generate credentials from different sized lists"
            )
        username_pass_data = zip(unique_users, passwords)
    else:
        username_pass_data = itertools.product(unique_users, passwords)

    results = []
    client_id_values = list(aad_clients.items())
    endpoint_id_values = list(aad_endpoints.items())
    user_agent_values = list(user_agents.items())

    source_data = itertools.product(
        username_pass_data, client_id_values, endpoint_id_values, user_agent_values
    )

    for ((username, password), aad_client, aad_endpoint, user_agent) in source_data:
        results.append(
            Credential(
                conf.domain,
                username,
                password,
                aad_client,
                aad_endpoint,
                user_agent,
                conf.delay,
            )
        )

    return results


def get_shuffled_credentials(
    conf: Configuration, credentials: list[Credential]
) -> dict[str, list[Credential]]:
    temp_auth_creds = {}
    possible_auth_creds: dict[int, tuple[int, list[Credential]]] = {}

    username_grouping_func: Callable[
        [Credential], bool
    ] = lambda credential: credential.username

    for i in range(0, conf.shuffle_optimization_attempts):
        console.print_info(
            "Generated potential execution plan %d/%d"
            % (i + 1, conf.shuffle_optimization_attempts)
        )
        credentials_by_user = get_credentials_dict_by_key(
            credentials, username_grouping_func
        )

        for user in credentials_by_user.keys():
            random.shuffle(credentials_by_user[user])

        group_index = 0
        while sum([len(u) for u in credentials_by_user.values()]) > 0:
            cred_grouping = []
            users = [user for user, creds in credentials_by_user.items() if len(creds)]
            random.shuffle(users)

            while users:
                random_user_index = random.randrange(0, len(users))
                user = users.pop(random_user_index)

                random_cred_index = random.randrange(0, len(credentials_by_user[user]))
                random_cred = credentials_by_user[user].pop(random_cred_index)

                cred_grouping.append(random_cred)
            temp_auth_creds[group_index] = cred_grouping
            group_index += 1

        _insert_random_initial_delays(temp_auth_creds, conf.min_loop_delay)

        spray_runtime = get_spray_runtime(temp_auth_creds)
        possible_auth_creds[i] = (spray_runtime, temp_auth_creds)

    runtimes = [
        (spray_attempt[1][0], spray_attempt[0])
        for spray_attempt in possible_auth_creds.items()
    ]
    fastest_runtime = min(runtimes)
    slowest_runtime = max(runtimes)

    console.print_info(
        "Optimal execution plan identified (#%d)" % (fastest_runtime[1] + 1)
    )
    console.print_info(
        "Spraying will take %d seconds, %d seconds faster than the slowest execution plan generated"
        % (fastest_runtime[0], (slowest_runtime[0] - fastest_runtime[0]))
    )
    console.print_info(
        "This random execution plan will take %d seconds longer than spraying with a simple (non-random) execution plan"
        % (fastest_runtime[0] - (len(credentials) * conf.delay))
    )

    return possible_auth_creds[fastest_runtime[1]][1]
