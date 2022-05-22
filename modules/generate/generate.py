import click
from modules.generate.modes import audit, normal


@click.group("generate", help="Generate an execution plan to use for password spraying")
def group():
    pass


group.add_command(audit.command)
group.add_command(normal.command)
