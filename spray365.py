import sys

import click

from modules.core.output import console
from modules.generate import generate
from modules.review import review
from modules.spray import spray

version = "0.2.3"


@click.group(context_settings=dict(help_option_names=["-h", "--help"]))
def cli():
    pass


def version_check():
    if sys.version_info.major != 3:
        print("Spray365 requires Python 3")
        sys.exit(1)

    if sys.version_info.minor < 9:
        console.print_warning("Spray365 may not work on Python versions prior to 3.9")


cli.add_command(spray.command)
cli.add_command(generate.group)
cli.add_command(review.command)

if __name__ == "__main__":
    console.print_banner(version)
    version_check()
    cli(max_content_width=180)
