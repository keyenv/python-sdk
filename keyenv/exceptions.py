"""KeyEnv exceptions."""

from typing import Any


class KeyEnvError(Exception):
    """Exception raised for KeyEnv API errors."""

    def __init__(
        self,
        message: str,
        status: int = 0,
        code: str | None = None,
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.message = message
        self.status = status
        self.code = code
        self.details = details or {}

    def __str__(self) -> str:
        if self.status:
            return f"KeyEnvError({self.status}): {self.message}"
        return f"KeyEnvError: {self.message}"
