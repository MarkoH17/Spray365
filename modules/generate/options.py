import click
from click_option_group import optgroup
from modules.core.options.utilities import split_comma_separated_args

general_options = [
    click.option(
        "--execution_plan",
        "-ep",
        help="File path where execution plan should be saved",
        metavar="",
        type=click.File(mode="w"),
        required=True,
    ),
    click.option(
        "--domain",
        "-d",
        metavar="",
        type=str,
        help="Office 365 domain to authenticate against",
        required=True,
    ),
    click.option(
        "--delay",
        metavar="",
        type=int,
        help="Delay in seconds to wait between authentication attempts",
        default=30,
        show_default=True,
    ),
    click.option(
        "--min_loop_delay",
        "-mD",
        metavar="",
        type=int,
        help="Minimum time to wait between authentication attempts for a given user. This option takes into account the time one spray iteration will take, so a pre-authentication delay may not occur every time",
        default=0,
        show_default=True,
    ),
]

user_options = [
    optgroup.option(
        "--user_file",
        "-u",
        metavar="",
        type=click.File(mode="r"),
        help="File containing usernames to spray (one per line without domain)",
        required=True,
    )
]

password_options = [
    optgroup.option("--password", "-p", metavar="", type=str, help="Password to spray"),
    optgroup.option(
        "--password_file",
        "-pf",
        metavar="",
        type=click.File(mode="r"),
        help="File containing passwords to spray (one per line)",
    ),
    optgroup.option(
        "--passwords_in_userfile",
        metavar="",
        is_flag=True,
        help="Extract passwords from user_file (colon separated)",
    ),
]

shuffle_options = [
    optgroup.option(
        "--shuffle_auth_order",
        "-S",
        metavar="",
        is_flag=True,
        help="Shuffle order of authentication attempts so that each iteration (User1:Pass1, Us"
        "er2:Pass1, User3:Pass1) will be sprayed in a random order with a random arrangem"
        "ent of passwords, e.g (User4:Pass16, User13:Pass25, User19:Pass40). Be aware thi"
        "s option introduces the possibility that the time between consecutive authentica"
        "tion attempts for a given user may occur DELAY seconds apart. Consider using the"
        "-mD/--min_loop_delay option to enforce a minimum delay between authenticati"
        "on attempts for any given user.",
    ),
    optgroup.option(
        "--shuffle_optimization_attempts",
        "-SO",
        metavar="",
        type=int,
        default=10,
        show_default=True,
    ),
]

authentication_options = [
    optgroup.option(
        "--aad_client",
        "-cID",
        metavar="",
        type=str,
        help="Client ID used during authentication. Leave unspecified for random selection, or provide a comma-separated string",
        callback=split_comma_separated_args,
    ),
    optgroup.option(
        "--aad_endpoint",
        "-eID",
        metavar="",
        type=str,
        help="Endpoint ID used during authentication. Leave unspecified for random selection, or provide a comma-separated string",
        callback=split_comma_separated_args,
    ),
]

user_agent_options = [
    optgroup.option(
        "--custom_user_agent",
        "-cUA",
        metavar="",
        type=str,
        help="Set custom user agent for authentication requests",
    ),
    optgroup.option(
        "--random_user_agent",
        "-rUA",
        metavar="",
        is_flag=True,
        help="Randomize user agent for authentication requests",
        default=True,
        show_default=True,
    ),
]
