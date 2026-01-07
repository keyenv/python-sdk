"""KeyEnv API client."""

import os
from datetime import datetime
from typing import Any

import httpx

from .exceptions import KeyEnvError
from .types import (
    BulkImportResult,
    BulkSecretItem,
    Environment,
    Project,
    ProjectWithEnvironments,
    Secret,
    SecretHistory,
    SecretWithValue,
    User,
)

BASE_URL = "https://api.keyenv.dev"
DEFAULT_TIMEOUT = 30.0


class KeyEnv:
    """KeyEnv API client for managing secrets.

    Example:
        >>> from keyenv import KeyEnv
        >>> client = KeyEnv(token="your-service-token")
        >>> secrets = client.export_secrets("project-id", "production")
    """

    def __init__(self, token: str, timeout: float = DEFAULT_TIMEOUT):
        """Initialize the KeyEnv client.

        Args:
            token: Service token for authentication.
            timeout: Request timeout in seconds (default: 30).
        """
        if not token:
            raise ValueError("KeyEnv token is required")

        self._token = token
        self._timeout = timeout
        self._client = httpx.Client(
            base_url=BASE_URL,
            timeout=timeout,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "User-Agent": "keyenv-python/1.0.0",
            },
        )

    def __enter__(self) -> "KeyEnv":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    def _request(self, method: str, path: str, json: dict[str, Any] | None = None) -> Any:
        """Make an HTTP request to the API."""
        try:
            response = self._client.request(method, path, json=json)

            if response.status_code == 204:
                return None

            if not response.is_success:
                try:
                    error_data = response.json()
                    raise KeyEnvError(
                        error_data.get("error", "Unknown error"),
                        response.status_code,
                        error_data.get("code"),
                        error_data.get("details"),
                    )
                except (ValueError, KeyError):
                    raise KeyEnvError(response.text or "Unknown error", response.status_code)

            return response.json()

        except httpx.TimeoutException:
            raise KeyEnvError("Request timeout", 408)
        except httpx.RequestError as e:
            raise KeyEnvError(str(e), 0)

    # =========================================================================
    # Authentication
    # =========================================================================

    def get_current_user(self) -> User:
        """Get the current user or service token info."""
        data = self._request("GET", "/api/v1/users/me")
        return User.from_dict(data)

    def validate_token(self) -> User:
        """Validate the token and return user info."""
        return self.get_current_user()

    # =========================================================================
    # Projects
    # =========================================================================

    def list_projects(self) -> list[Project]:
        """List all accessible projects."""
        data = self._request("GET", "/api/v1/projects")
        return [Project.from_dict(p) for p in data.get("projects", [])]

    def get_project(self, project_id: str) -> ProjectWithEnvironments:
        """Get a project by ID."""
        data = self._request("GET", f"/api/v1/projects/{project_id}")
        return ProjectWithEnvironments.from_dict(data)

    def create_project(self, team_id: str, name: str) -> Project:
        """Create a new project."""
        data = self._request("POST", "/api/v1/projects", {"team_id": team_id, "name": name})
        return Project.from_dict(data)

    def delete_project(self, project_id: str) -> None:
        """Delete a project."""
        self._request("DELETE", f"/api/v1/projects/{project_id}")

    # =========================================================================
    # Environments
    # =========================================================================

    def list_environments(self, project_id: str) -> list[Environment]:
        """List environments in a project."""
        data = self._request("GET", f"/api/v1/projects/{project_id}/environments")
        return [Environment.from_dict(e) for e in data.get("environments", [])]

    def create_environment(
        self, project_id: str, name: str, inherits_from: str | None = None
    ) -> Environment:
        """Create a new environment."""
        payload: dict[str, Any] = {"name": name}
        if inherits_from:
            payload["inherits_from"] = inherits_from
        data = self._request("POST", f"/api/v1/projects/{project_id}/environments", payload)
        return Environment.from_dict(data)

    def delete_environment(self, project_id: str, environment: str) -> None:
        """Delete an environment."""
        self._request("DELETE", f"/api/v1/projects/{project_id}/environments/{environment}")

    # =========================================================================
    # Secrets
    # =========================================================================

    def list_secrets(self, project_id: str, environment: str) -> list[Secret]:
        """List secrets in an environment (keys and metadata only)."""
        data = self._request(
            "GET", f"/api/v1/projects/{project_id}/environments/{environment}/secrets"
        )
        return [Secret.from_dict(s) for s in data.get("secrets", [])]

    def export_secrets(self, project_id: str, environment: str) -> list[SecretWithValue]:
        """Export all secrets with their decrypted values."""
        data = self._request(
            "GET", f"/api/v1/projects/{project_id}/environments/{environment}/secrets/export"
        )
        return [SecretWithValue.from_dict(s) for s in data.get("secrets", [])]

    def export_secrets_as_dict(self, project_id: str, environment: str) -> dict[str, str]:
        """Export secrets as a key-value dictionary."""
        secrets = self.export_secrets(project_id, environment)
        return {s.key: s.value for s in secrets}

    def get_secret(self, project_id: str, environment: str, key: str) -> SecretWithValue:
        """Get a single secret with its value."""
        data = self._request(
            "GET", f"/api/v1/projects/{project_id}/environments/{environment}/secrets/{key}"
        )
        return SecretWithValue.from_dict(data.get("secret", data))

    def create_secret(
        self,
        project_id: str,
        environment: str,
        key: str,
        value: str,
        description: str | None = None,
    ) -> Secret:
        """Create a new secret."""
        payload: dict[str, Any] = {"key": key, "value": value}
        if description:
            payload["description"] = description
        data = self._request(
            "POST",
            f"/api/v1/projects/{project_id}/environments/{environment}/secrets",
            payload,
        )
        return Secret.from_dict(data.get("secret", data))

    def update_secret(
        self,
        project_id: str,
        environment: str,
        key: str,
        value: str,
        description: str | None = None,
    ) -> Secret:
        """Update a secret's value."""
        payload: dict[str, Any] = {"value": value}
        if description is not None:
            payload["description"] = description
        data = self._request(
            "PUT",
            f"/api/v1/projects/{project_id}/environments/{environment}/secrets/{key}",
            payload,
        )
        return Secret.from_dict(data.get("secret", data))

    def set_secret(
        self,
        project_id: str,
        environment: str,
        key: str,
        value: str,
        description: str | None = None,
    ) -> Secret:
        """Set a secret (create or update)."""
        try:
            return self.update_secret(project_id, environment, key, value, description)
        except KeyEnvError as e:
            if e.status == 404:
                return self.create_secret(project_id, environment, key, value, description)
            raise

    def delete_secret(self, project_id: str, environment: str, key: str) -> None:
        """Delete a secret."""
        self._request(
            "DELETE", f"/api/v1/projects/{project_id}/environments/{environment}/secrets/{key}"
        )

    def get_secret_history(
        self, project_id: str, environment: str, key: str
    ) -> list[SecretHistory]:
        """Get secret version history."""
        data = self._request(
            "GET",
            f"/api/v1/projects/{project_id}/environments/{environment}/secrets/{key}/history",
        )
        return [SecretHistory.from_dict(h) for h in data.get("history", [])]

    def bulk_import(
        self,
        project_id: str,
        environment: str,
        secrets: list[BulkSecretItem] | list[dict[str, str]],
        overwrite: bool = False,
    ) -> BulkImportResult:
        """Bulk import secrets."""
        secret_list = [
            s.to_dict() if isinstance(s, BulkSecretItem) else s for s in secrets
        ]
        data = self._request(
            "POST",
            f"/api/v1/projects/{project_id}/environments/{environment}/secrets/bulk",
            {"secrets": secret_list, "overwrite": overwrite},
        )
        return BulkImportResult.from_dict(data)

    # =========================================================================
    # Utilities
    # =========================================================================

    def load_env(self, project_id: str, environment: str) -> int:
        """Load secrets into os.environ.

        Returns:
            Number of secrets loaded.
        """
        secrets = self.export_secrets(project_id, environment)
        for secret in secrets:
            os.environ[secret.key] = secret.value
        return len(secrets)

    def generate_env_file(self, project_id: str, environment: str) -> str:
        """Generate .env file content from secrets."""
        secrets = self.export_secrets(project_id, environment)
        lines = [
            "# Generated by KeyEnv",
            f"# Environment: {environment}",
            f"# Generated at: {datetime.utcnow().isoformat()}Z",
            "",
        ]

        for secret in secrets:
            value = secret.value
            if "\n" in value or '"' in value or "'" in value or " " in value:
                escaped = value.replace("\\", "\\\\").replace('"', '\\"')
                lines.append(f'{secret.key}="{escaped}"')
            else:
                lines.append(f"{secret.key}={value}")

        return "\n".join(lines) + "\n"
