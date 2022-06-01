from __future__ import annotations


class Credential:
    def __init__(
        self,
        domain: str,
        username: str,
        password: str,
        client_id: tuple[str, str],
        endpoint: tuple[str, str],
        user_agent: str,
        delay: int,
        initial_delay: int = 0,
    ):
        self.domain: str = domain
        self.username: str = username
        self.password: str = password
        self.client_id: tuple[str, str] = client_id
        self.endpoint: tuple[str, str] = endpoint
        self.user_agent: str = user_agent
        self.delay: int = delay
        self.initial_delay: int = initial_delay

    @property
    def email_address(self) -> str:
        if self.username and self.domain:
            return "%s@%s" % (self.username, self.domain)
        else:
            return None
