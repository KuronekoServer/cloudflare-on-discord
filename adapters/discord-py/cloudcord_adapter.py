"""CloudCord endpoint adapter for discord.py 2.7.1.

Call ``configure`` before constructing ``discord.Client`` or ``commands.Bot``.
The official library discovers the Gateway through the configured REST API.
"""

from urllib.parse import urlsplit, urlunsplit

import discord.http


def configure(origin: str) -> str:
    """Point discord.py's v10 REST and Gateway discovery at CloudCord."""
    parsed = urlsplit(origin)
    localhost = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and localhost):
        raise ValueError("CloudCord Bot API origin must use HTTPS")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("CloudCord Bot API origin must not contain credentials or a query")
    normalized = urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "")
    )
    discord.http.Route.BASE = f"{normalized}/api/v10"
    return discord.http.Route.BASE
