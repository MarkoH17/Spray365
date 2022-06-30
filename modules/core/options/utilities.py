from __future__ import annotations

import click


def split_comma_separated_args(ctx: click.Context, param: str, value: any) -> list[str]:
    result = []

    if value is None:
        return result

    for item in value.split(","):
        item = item.strip()
        if len(item) > 0:
            result.append(item)

    if len(result) < 1:
        raise click.BadOptionUsage(
            "Invalid comma-separated values specified for '%s' parameter" % param
        )

    return result


def add_options(options: list[any]):
    def _add_options(func):
        for option in reversed(options):
            func = option(func)
        return func

    return _add_options
