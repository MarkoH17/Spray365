import json
from typing import Callable

import click
from click_option_group import (AllOptionGroup,
                                RequiredMutuallyExclusiveOptionGroup, optgroup)

from modules.core import constants
from modules.core.credential import Credential
from modules.core.options.utilities import add_options
from modules.core.output import console
from modules.generate import helpers, options
from modules.generate.configuration import Configuration


@click.command(
    "audit",
    help="Generate an execution plan to identify flaws in MFA / Conditional Access Policies. This works best with with known credentials.",
)
@click.pass_context
@add_options(options.general_options)
@optgroup.group("User options")
@add_options(options.user_options)
@optgroup.group("Password options", cls=RequiredMutuallyExclusiveOptionGroup)
@add_options(options.password_options)
@optgroup.group("Shuffle options", cls=AllOptionGroup)
@add_options(options.shuffle_options)
def command(
    ctx,
    execution_plan,
    domain,
    delay,
    min_loop_delay,
    user_file,
    password,
    password_file,
    passwords_in_userfile,
    shuffle_auth_order,
    shuffle_optimization_attempts,
):
    conf = Configuration(ctx)
    ctx.obj = conf

    helpers.check_if_execution_plan_exists(conf)

    if conf.passwords_in_userfile:
        users, passwords = helpers.get_users_and_passwords(conf)
    else:
        users = helpers.get_users(conf)
        passwords = helpers.get_passwords(conf)

    console.print_info(
        "Generating audit-mode execution plan from %d users and %d passwords"
        % (len(users), len(passwords))
    )

    console.print_warning(
        "Audit-mode execution plans contain permutations of all possible usernames, passwords, user-agents, aad_clients, and aad_endpoints"
    )

    if conf.shuffle_auth_order and not conf.min_loop_delay:
        console.print_warning(
            "This random execution plan does not enforce a minimum cred loop delay (-mD / --min_cred_loop_delay). This may cause account lockouts!"
        )

    client_ids = constants.client_ids
    endpoint_ids = constants.endpoint_ids
    user_agents = constants.user_agents

    raw_credentials = helpers.get_credential_products(
        conf,
        users,
        passwords,
        client_ids,
        endpoint_ids,
        user_agents,
        bool(conf.passwords_in_userfile),
    )

    console.print_info(
        "Generated execution plan with %d credentials" % (len(raw_credentials))
    )

    if conf.shuffle_auth_order:
        credentials = helpers.get_shuffled_credentials(conf, raw_credentials)
    else:
        password_grouping_func: Callable[
            [Credential], bool
        ] = lambda credential: credential.password
        credentials = helpers.get_credentials_dict_by_key(
            raw_credentials, password_grouping_func
        )

    cred_execution_plan = []

    for auth_cred_group in credentials.keys():
        cred_execution_plan.extend(credentials[auth_cred_group])

    json_execution_plan = json.dumps(cred_execution_plan, default=lambda o: o.__dict__)

    execution_plan.write(json_execution_plan)
