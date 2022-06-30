from __future__ import annotations

import click


class Configuration:
    def __init__(self, context: click.Context):
        # General Options
        self.execution_plan: click.File = None
        self.domain: str = None
        self.delay: int = None
        self.min_loop_delay: int = None

        # User Options
        self.user_file: str = None

        # Password Options
        self.password: str = None
        self.password_file: str = None
        self.passwords_in_userfile: bool = None

        # Authentication Options
        self.aad_client: list[str] = None
        self.aad_endpoint: list[str] = None

        # User Agent Options
        self.custom_user_agent: str = None
        self.random_user_agent: bool = None

        # Shuffle Options
        self.shuffle_auth_order: bool = None
        self.shuffle_optimization_attempts: int = None

        self._parse(context)

    def _parse(self, context: click.Context):
        for (param, param_value) in context.params.items():
            if hasattr(self, param):
                setattr(self, param, param_value)
