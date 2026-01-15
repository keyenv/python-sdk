"""KeyEnv type definitions."""

from dataclasses import dataclass
from typing import Any, Literal

EnvironmentRole = Literal["none", "read", "write", "admin"]


@dataclass
class User:
    """User or service token info."""

    id: str
    email: str | None = None
    name: str | None = None
    clerk_id: str | None = None
    avatar_url: str | None = None
    auth_type: str | None = None
    team_id: str | None = None
    project_ids: list[str] | None = None
    scopes: list[str] | None = None
    created_at: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "User":
        return cls(
            id=data["id"],
            email=data.get("email"),
            name=data.get("name"),
            clerk_id=data.get("clerk_id"),
            avatar_url=data.get("avatar_url"),
            auth_type=data.get("auth_type"),
            team_id=data.get("team_id"),
            project_ids=data.get("project_ids"),
            scopes=data.get("scopes"),
            created_at=data.get("created_at"),
        )


@dataclass
class Project:
    """Project."""

    id: str
    team_id: str
    name: str
    slug: str
    description: str | None = None
    created_at: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Project":
        return cls(
            id=data["id"],
            team_id=data["team_id"],
            name=data["name"],
            slug=data["slug"],
            description=data.get("description"),
            created_at=data.get("created_at"),
        )


@dataclass
class Environment:
    """Environment."""

    id: str
    project_id: str
    name: str
    inherits_from: str | None = None
    created_at: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Environment":
        return cls(
            id=data["id"],
            project_id=data["project_id"],
            name=data["name"],
            inherits_from=data.get("inherits_from"),
            created_at=data.get("created_at"),
        )


@dataclass
class ProjectWithEnvironments(Project):
    """Project with environments."""

    environments: list[Environment] | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProjectWithEnvironments":
        envs = data.get("environments", [])
        return cls(
            id=data["id"],
            team_id=data["team_id"],
            name=data["name"],
            slug=data["slug"],
            description=data.get("description"),
            created_at=data.get("created_at"),
            environments=[Environment.from_dict(e) for e in envs] if envs else None,
        )


@dataclass
class Secret:
    """Secret (without value)."""

    id: str
    environment_id: str
    key: str
    type: str
    version: int
    description: str | None = None
    created_at: str | None = None
    updated_at: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Secret":
        return cls(
            id=data["id"],
            environment_id=data["environment_id"],
            key=data["key"],
            type=data.get("type", "string"),
            version=data["version"],
            description=data.get("description"),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
        )


@dataclass
class SecretWithValue(Secret):
    """Secret with decrypted value."""

    value: str = ""
    inherited_from: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SecretWithValue":
        return cls(
            id=data["id"],
            environment_id=data["environment_id"],
            key=data["key"],
            type=data.get("type", "string"),
            version=data["version"],
            description=data.get("description"),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
            value=data.get("value", ""),
            inherited_from=data.get("inherited_from"),
        )


@dataclass
class SecretHistory:
    """Secret history entry."""

    id: str
    secret_id: str
    value: str
    version: int
    changed_by: str | None = None
    changed_at: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SecretHistory":
        return cls(
            id=data["id"],
            secret_id=data["secret_id"],
            value=data["value"],
            version=data["version"],
            changed_by=data.get("changed_by"),
            changed_at=data.get("changed_at"),
        )


@dataclass
class BulkSecretItem:
    """Bulk import request item."""

    key: str
    value: str
    description: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"key": self.key, "value": self.value}
        if self.description:
            d["description"] = self.description
        return d


@dataclass
class BulkImportResult:
    """Bulk import result."""

    created: int
    updated: int
    skipped: int

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BulkImportResult":
        return cls(
            created=data.get("created", 0),
            updated=data.get("updated", 0),
            skipped=data.get("skipped", 0),
        )


@dataclass
class EnvironmentPermission:
    """Environment permission for a user."""

    id: str
    environment_id: str
    user_id: str
    role: EnvironmentRole
    user_email: str | None = None
    user_name: str | None = None
    granted_by: str | None = None
    created_at: str = ""
    updated_at: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EnvironmentPermission":
        return cls(
            id=data["id"],
            environment_id=data["environment_id"],
            user_id=data["user_id"],
            role=data["role"],
            user_email=data.get("user_email"),
            user_name=data.get("user_name"),
            granted_by=data.get("granted_by"),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
        )


@dataclass
class MyPermission:
    """User's own permission for an environment."""

    environment_id: str
    environment_name: str
    role: EnvironmentRole
    can_read: bool
    can_write: bool
    can_admin: bool

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MyPermission":
        return cls(
            environment_id=data["environment_id"],
            environment_name=data["environment_name"],
            role=data["role"],
            can_read=data["can_read"],
            can_write=data["can_write"],
            can_admin=data["can_admin"],
        )


@dataclass
class ProjectDefault:
    """Default permission for an environment in a project."""

    id: str
    project_id: str
    environment_name: str
    default_role: EnvironmentRole
    created_at: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProjectDefault":
        return cls(
            id=data["id"],
            project_id=data["project_id"],
            environment_name=data["environment_name"],
            default_role=data["default_role"],
            created_at=data.get("created_at", ""),
        )
