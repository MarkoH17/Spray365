import click
from modules.core.output import console
from modules.generate import generate
from modules.spray import spray
from modules.review import review

version = "0.2.0-beta"


@click.group(context_settings=dict(help_option_names=["-h", "--help"]))
def cli():
    pass


cli.add_command(spray.command)
cli.add_command(generate.group)
cli.add_command(review.command)

if __name__ == "__main__":
    console.print_banner(version)
    cli(max_content_width=180)
