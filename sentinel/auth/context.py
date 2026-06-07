"""Request-scoped authenticated principal.

On the HTTP transport, each request validates a Bearer JWT and stores the
resulting Principal in a ContextVar. The middleware pipeline reads it to
attribute the call to the right analyst (from the JWT `sub`). On stdio (a
trusted local process) no principal is set and the static settings identity
is used instead.
"""

from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Principal:
    analyst_id: str  # JWT `sub`
    role: str  # analyst | senior_analyst | admin
    scopes: tuple[str, ...] = ()
    claims: dict[str, Any] = field(default_factory=dict)

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes


_current_principal: ContextVar[Principal | None] = ContextVar("current_principal", default=None)


def get_current_principal() -> Principal | None:
    return _current_principal.get()


def set_current_principal(principal: Principal | None) -> Token[Principal | None]:
    return _current_principal.set(principal)


def reset_current_principal(token: Token[Principal | None]) -> None:
    _current_principal.reset(token)
