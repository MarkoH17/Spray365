import datetime
import random
import sys
import typing

import click
from colorama import Fore


def print_banner(version: str):

    possible_colors = [
        Fore.CYAN,
        Fore.GREEN,
        Fore.RED,
        Fore.LIGHTBLUE_EX,
        Fore.LIGHTCYAN_EX,
        Fore.LIGHTGREEN_EX,
        Fore.LIGHTMAGENTA_EX,
        Fore.LIGHTRED_EX,
        Fore.LIGHTYELLOW_EX,
    ]

    colors = random.sample(possible_colors, 8)
    colors_tuple = tuple(colors)

    lines = [
        "\n%s███████╗%s██████╗ %s██████╗ %s █████╗ %s██╗   ██╗%s██████╗ %s ██████╗ %s███████╗"
        % colors_tuple,
        "%s██╔════╝%s██╔══██╗%s██╔══██╗%s██╔══██╗%s╚██╗ ██╔╝%s╚════██╗%s██╔════╝ %s██╔════╝"
        % colors_tuple,
        "%s███████╗%s██████╔╝%s██████╔╝%s███████║%s ╚████╔╝ %s █████╔╝%s███████╗ %s███████╗"
        % colors_tuple,
        "%s╚════██║%s██╔═══╝ %s██╔══██╗%s██╔══██║%s  ╚██╔╝  %s ╚═══██╗%s██╔═══██╗%s╚════██║"
        % colors_tuple,
        "%s███████║%s██║     %s██║  ██║%s██║  ██║%s   ██║   %s██████╔╝%s ██████╔╝%s███████║"
        % colors_tuple,
        "%s╚══════╝%s╚═╝     %s╚═╝  ╚═╝%s╚═╝  ╚═╝%s   ╚═╝   %s╚═════╝ %s ╚═════╝ %s╚══════╝"
        % colors_tuple,
        "%30sBy MarkoH17 (https://github.com/MarkoH17)" % colors[3],
        "%s%sVersion: %s\n%s"
        % ((" " * (57 - len(version))), colors[3], version, Fore.RESET),
    ]
    [click.echo(line) for line in lines]


def print_info(message: str):
    _print_log("INFO", message, "bright_blue")


def print_warning(message: str):
    _print_log("WARN", message, "yellow")


def print_error(message: str, fatal: bool = True):
    print("\r", end="")
    _print_log("ERROR", message, "red")
    if fatal:
        sys.exit(1)


def _print_log(level: str, message: str, color: str):
    output = "[%s - %s]: %s" % (get_time_str(), level, message)

    click.echo(click.style(output, fg=color))


# TODO: Replace typing.Union below with modern Union added in PEP 604 (Python 3.10+)
def print_spray_output(
    spray_idx: int,
    spray_size: int,
    client_id: str,
    endpoint_id: str,
    user_agent: str,
    username: str,
    password: str,
    status_message: str,
    line_terminator: typing.Union[str, None],
    flush: bool,
):
    print(
        "%s[%s - SPRAY %s/%d] (%s%s%s->%s%s%s->%s%s%s): %s%s / %s%s %s%s"
        % (
            Fore.LIGHTBLUE_EX,
            get_time_str(),
            str(spray_idx).zfill(len(str(spray_size))),
            spray_size,
            Fore.LIGHTRED_EX,
            user_agent,
            Fore.LIGHTBLUE_EX,
            Fore.LIGHTCYAN_EX,
            client_id,
            Fore.LIGHTBLUE_EX,
            Fore.LIGHTGREEN_EX,
            endpoint_id,
            Fore.LIGHTBLUE_EX,
            Fore.LIGHTMAGENTA_EX,
            username,
            Fore.LIGHTMAGENTA_EX,
            password,
            status_message,
            Fore.RESET,
        ),
        end=line_terminator,
        flush=flush,
    )


def get_time_str():
    date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return date_str
