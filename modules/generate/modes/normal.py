import json
from typing import Callable

import click
from click_option_group import (AllOptionGroup, MutuallyExclusiveOptionGroup,
                                RequiredMutuallyExclusiveOptionGroup, optgroup)

from modules.core import constants
from modules.core.credential import Credential
from modules.core.options.utilities import add_options
from modules.core.output import console
from modules.generate import helpers, options
from modules.generate.configuration import Configuration


@click.command("normal", help="Generate a vanilla (normal) execution plan")
@click.pass_context
@add_options(options.general_options)
@optgroup.group("User options")
@add_options(options.user_options)
@optgroup.group("Password options", cls=RequiredMutuallyExclusiveOptionGroup)
@add_options(options.password_options)
@optgroup.group("Authentication options")
@add_options(options.authentication_options)
@optgroup.group("User Agent options", cls=MutuallyExclusiveOptionGroup)
@add_options(options.user_agent_options)
@optgroup.group("Shuffle options", cls=AllOptionGroup)
@add_options(options.shuffle_options)
def command(
    ctx: click.Context,
    execution_plan,
    domain,
    delay,
    min_loop_delay,
    user_file,
    password,
    password_file,
    passwords_in_userfile,
    aad_client,
    aad_endpoint,
    custom_user_agent,
    random_user_agent,
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
        "Generating execution plan from %d users and %d passwords"
        % (len(users), len(passwords))
    )

    if not conf.aad_client:
        console.print_info("Execution plan will use random AAD client IDs")
        client_ids = constants.client_ids
    else:
        console.print_info("Execution plan will use the provided AAD client ID(s)")
        client_ids = helpers.get_custom_aad_values("custom_cid_", conf.aad_client)

    if not conf.aad_endpoint:
        console.print_info("Execution plan will use random AAD endpoint IDs")
        endpoint_ids = constants.endpoint_ids
    else:
        console.print_info("Execution plan will use the provided AAD endpoint ID(s)")
        endpoint_ids = helpers.get_custom_aad_values("custom_eid_", conf.aad_endpoint)

    if conf.custom_user_agent:
        user_agents = {"custom_user_agent": conf.custom_user_agent}
    elif conf.random_user_agent:
        user_agents = constants.user_agents
    else:
        user_agents = {"default": list(constants.user_agents.values())[-1]}

    raw_credentials = helpers.get_credentials(
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
        if not conf.min_loop_delay:
            console.print_warning(
                "This random execution plan does not enforce a minimum cred loop delay (-mD / --min_cred_loop_delay). This may cause account lockouts!"
            )
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

    with execution_plan.open() as ep_file:
        ep_file.write(json_execution_plan)
