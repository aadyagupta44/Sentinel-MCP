"""Keycloak identity adapter — user profiles, groups, login events, account actions.

Uses Keycloak Admin REST API.
Requires a service account with view-users and manage-users roles.
Self-hosted — Keycloak runs in docker-compose. Free, no external dependency.

Never returns raw Keycloak internal IDs or tokens in tool responses.
"""

from datetime import datetime, timedelta, timezone
from typing import Any

from sentinel.adapters.base import BaseAdapter, CircuitOpenError
from sentinel.config import get_settings
from sentinel.tools import mock_data as mock


class KeycloakAdapter(BaseAdapter):
    adapter_name = "keycloak"

    def __init__(self) -> None:
        super().__init__()
        settings = get_settings()
        self._base_url = settings.keycloak_url.rstrip("/")
        self._realm = settings.keycloak_realm
        self._admin_url = f"{self._base_url}/admin/realms/{self._realm}"
        self._token_url = f"{self._base_url}/realms/master/protocol/openid-connect/token"
        self._access_token: str | None = None
        self._token_expires: datetime = datetime.now(timezone.utc)

    async def get_user(self, email: str) -> dict[str, Any] | None:
        if self.is_mock:
            return mock.get_user(email)

        user_id = await self._find_user_id(email)
        if not user_id:
            return None

        token = await self._get_token()
        if not token:
            return None

        if self._breaker.is_open():
            raise CircuitOpenError(self.adapter_name)

        try:
            resp = await self._call(
                "GET",
                f"{self._admin_url}/users/{user_id}",
                span_name="get_user",
                headers={"Authorization": f"Bearer {token}"},
            )
            resp.raise_for_status()
            raw = resp.json()
            return self._sanitize_user(raw)
        except CircuitOpenError:
            raise
        except Exception as exc:
            self._log.warning("keycloak_get_user_failed", error=str(exc), email=email)
            return None

    async def get_login_events(self, email: str, days: int = 7) -> list[dict[str, Any]]:
        if self.is_mock:
            return mock.get_logins(email, days)

        user_id = await self._find_user_id(email)
        if not user_id:
            return []

        token = await self._get_token()
        if not token:
            return []

        if self._breaker.is_open():
            raise CircuitOpenError(self.adapter_name)

        since = datetime.now(timezone.utc) - timedelta(days=days)
        try:
            resp = await self._call(
                "GET",
                f"{self._admin_url}/events",
                span_name="get_login_events",
                headers={"Authorization": f"Bearer {token}"},
                params={
                    "type": "LOGIN",
                    "user": user_id,
                    "dateFrom": since.strftime("%Y-%m-%d"),
                    "max": 200,
                },
            )
            resp.raise_for_status()
            events = resp.json()
            return [self._sanitize_event(e) for e in events]
        except CircuitOpenError:
            raise
        except Exception as exc:
            self._log.warning("keycloak_login_events_failed", error=str(exc), email=email)
            return []

    async def suspend_user(self, email: str) -> dict[str, Any]:
        if self.is_mock:
            return {"email": email, "action": "suspended", "mock": True}

        user_id = await self._find_user_id(email)
        if not user_id:
            return {"error": f"User '{email}' not found", "code": "NOT_FOUND"}

        token = await self._get_token()
        if not token:
            return {"error": "Could not obtain Keycloak admin token", "code": "AUTH_FAILED"}

        if self._breaker.is_open():
            raise CircuitOpenError(self.adapter_name)

        try:
            resp = await self._call(
                "PUT",
                f"{self._admin_url}/users/{user_id}",
                span_name="suspend_user",
                json={"enabled": False},
                headers={"Authorization": f"Bearer {token}"},
            )
            resp.raise_for_status()
            return {"email": email, "action": "suspended", "user_id": user_id}
        except CircuitOpenError:
            raise
        except Exception as exc:
            self._log.warning("keycloak_suspend_failed", error=str(exc), email=email)
            return {"error": str(exc), "code": "KEYCLOAK_ERROR"}

    # ── Internal helpers ──────────────────────────────────────────────────────

    async def _get_token(self) -> str | None:
        """Obtain a Keycloak admin token using client credentials."""
        if self._access_token and datetime.now(timezone.utc) < self._token_expires:
            return self._access_token

        settings = get_settings()
        try:
            resp = await self._retry_request(
                "POST",
                self._token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": settings.oauth_client_id,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            self._access_token = data.get("access_token")
            expires_in = data.get("expires_in", 300)
            self._token_expires = datetime.now(timezone.utc) + timedelta(seconds=expires_in - 30)
            return self._access_token
        except Exception as exc:
            self._log.warning("keycloak_token_failed", error=str(exc))
            return None

    async def _find_user_id(self, email: str) -> str | None:
        token = await self._get_token()
        if not token:
            return None
        try:
            resp = await self._retry_request(
                "GET",
                f"{self._admin_url}/users",
                params={"email": email, "exact": True, "max": 1},
                headers={"Authorization": f"Bearer {token}"},
            )
            resp.raise_for_status()
            users = resp.json()
            return users[0]["id"] if users else None
        except Exception as exc:
            self._log.warning("keycloak_find_user_failed", error=str(exc), email=email)
            return None

    @staticmethod
    def _sanitize_user(raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "email": raw.get("email", ""),
            "name": f"{raw.get('firstName', '')} {raw.get('lastName', '')}".strip(),
            "account_status": "active" if raw.get("enabled") else "disabled",
            "created_at": raw.get("createdTimestamp", ""),
            "mfa_enabled": bool(raw.get("requiredActions", [])),
            "groups": [],
        }

    @staticmethod
    def _sanitize_event(event: dict[str, Any]) -> dict[str, Any]:
        details = event.get("details", {})
        return {
            "timestamp": datetime.fromtimestamp(event.get("time", 0) / 1000, tz=timezone.utc).isoformat(),
            "ip_address": event.get("ipAddress", ""),
            "device": details.get("auth_method", "Unknown"),
            "success": event.get("type") == "LOGIN",
            "country": "",
            "mfa_method": details.get("auth_type"),
        }


_adapter: KeycloakAdapter | None = None


def get_keycloak_adapter() -> KeycloakAdapter:
    global _adapter
    if _adapter is None:
        _adapter = KeycloakAdapter()
    return _adapter
