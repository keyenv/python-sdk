"""Integration tests for KeyEnv Python SDK.

These tests run against a live test API server and verify real API calls.

Requirements:
- Test API running at http://localhost:8081/api/v1 (via `make test-infra-up`)
- Environment variables:
  - KEYENV_API_URL: API base URL (e.g., http://localhost:8081)
  - KEYENV_TOKEN: Service token for authentication
  - KEYENV_PROJECT: Project slug (default: sdk-test)

Run with:
    KEYENV_API_URL=http://localhost:8081 \
    KEYENV_TOKEN=env_test_integration_token_12345 \
    pytest tests/test_integration.py -v
"""

import os
import time

import pytest

from keyenv import KeyEnv, KeyEnvError
from keyenv.types import BulkSecretItem

# Skip all tests in this module if KEYENV_API_URL is not set
pytestmark = pytest.mark.skipif(
    not os.environ.get("KEYENV_API_URL"),
    reason="Integration tests require KEYENV_API_URL environment variable",
)


def get_unique_key(prefix: str = "TEST") -> str:
    """Generate a unique key with timestamp to avoid conflicts."""
    return f"{prefix}_{int(time.time() * 1000)}"


@pytest.fixture(scope="module")
def client():
    """Create a KeyEnv client for integration tests."""
    api_url = os.environ.get("KEYENV_API_URL")
    token = os.environ.get("KEYENV_TOKEN", "env_test_integration_token_12345")

    if not api_url:
        pytest.skip("KEYENV_API_URL not set")

    client = KeyEnv(token=token, base_url=api_url)
    yield client
    client.close()


@pytest.fixture(scope="module")
def project_slug():
    """Get the project slug for tests."""
    return os.environ.get("KEYENV_PROJECT", "sdk-test")


@pytest.fixture(scope="module")
def environment():
    """Get the environment name for tests."""
    return "development"


class TestAuthentication:
    """Test authentication and token validation."""

    def test_validate_token(self, client):
        """Test that the token is valid and can authenticate."""
        user = client.validate_token()
        assert user is not None
        assert user.id is not None

    def test_get_current_user(self, client):
        """Test getting current user/token info."""
        user = client.get_current_user()
        assert user is not None
        assert user.id is not None
        # Service tokens have auth_type set
        if user.auth_type:
            assert user.auth_type == "service_token"


class TestProjects:
    """Test project operations."""

    def test_list_projects(self, client):
        """Test listing accessible projects."""
        projects = client.list_projects()
        assert isinstance(projects, list)
        # Should have at least one project (the test project)
        assert len(projects) >= 1

    def test_list_projects_contains_test_project(self, client, project_slug):
        """Test that the test project is in the list."""
        projects = client.list_projects()
        project_slugs = [p.slug for p in projects]
        assert project_slug in project_slugs

    def test_get_project(self, client, project_slug):
        """Test getting a specific project."""
        project = client.get_project(project_slug)
        assert project is not None
        assert project.slug == project_slug
        assert project.name is not None
        # Project should have environments
        assert project.environments is not None
        assert len(project.environments) >= 1


class TestEnvironments:
    """Test environment operations."""

    def test_list_environments(self, client, project_slug):
        """Test listing environments in a project."""
        environments = client.list_environments(project_slug)
        assert isinstance(environments, list)
        assert len(environments) >= 1

    def test_list_environments_has_expected(self, client, project_slug):
        """Test that expected environments exist."""
        environments = client.list_environments(project_slug)
        env_names = [e.name for e in environments]
        # Test project should have these environments
        assert "development" in env_names


class TestSecrets:
    """Test secret CRUD operations."""

    @pytest.fixture(autouse=True)
    def setup_cleanup(self, client, project_slug, environment):
        """Track created secrets for cleanup."""
        self.created_keys: list[str] = []
        self.client = client
        self.project_slug = project_slug
        self.environment = environment
        yield
        # Cleanup: delete any secrets we created
        for key in self.created_keys:
            try:
                client.delete_secret(project_slug, environment, key)
            except KeyEnvError:
                pass  # Ignore errors during cleanup

    def _track_key(self, key: str):
        """Track a key for cleanup."""
        self.created_keys.append(key)

    def test_list_secrets(self, client, project_slug, environment):
        """Test listing secrets in an environment."""
        secrets = client.list_secrets(project_slug, environment)
        assert isinstance(secrets, list)
        # Each secret should have required fields
        for secret in secrets:
            assert secret.key is not None
            assert secret.environment_id is not None

    def test_export_secrets(self, client, project_slug, environment):
        """Test exporting secrets with values."""
        secrets = client.export_secrets(project_slug, environment)
        assert isinstance(secrets, list)
        # Each secret should have a value
        for secret in secrets:
            assert secret.key is not None
            assert secret.value is not None

    def test_export_secrets_as_dict(self, client, project_slug, environment):
        """Test exporting secrets as a dictionary."""
        env_dict = client.export_secrets_as_dict(project_slug, environment)
        assert isinstance(env_dict, dict)
        # All values should be strings
        for key, value in env_dict.items():
            assert isinstance(key, str)
            assert isinstance(value, str)

    def test_create_secret(self, client, project_slug, environment):
        """Test creating a new secret."""
        key = get_unique_key("CREATE")
        self._track_key(key)
        value = "test_value_create"
        description = "Test secret created by integration tests"

        secret = client.create_secret(
            project_slug, environment, key, value, description
        )

        assert secret is not None
        assert secret.key == key
        assert secret.description == description

        # Verify the secret was created by fetching it
        fetched = client.get_secret(project_slug, environment, key)
        assert fetched.value == value

    def test_get_secret(self, client, project_slug, environment):
        """Test getting a specific secret."""
        key = get_unique_key("GET")
        self._track_key(key)
        value = "test_value_get"

        # Create a secret first
        client.create_secret(project_slug, environment, key, value)

        # Get the secret
        secret = client.get_secret(project_slug, environment, key)
        assert secret is not None
        assert secret.key == key
        assert secret.value == value

    def test_update_secret(self, client, project_slug, environment):
        """Test updating a secret's value."""
        key = get_unique_key("UPDATE")
        self._track_key(key)
        initial_value = "initial_value"
        updated_value = "updated_value"

        # Create a secret
        client.create_secret(project_slug, environment, key, initial_value)

        # Update the secret
        updated = client.update_secret(project_slug, environment, key, updated_value)
        assert updated is not None

        # Verify the update
        fetched = client.get_secret(project_slug, environment, key)
        assert fetched.value == updated_value

    def test_set_secret_creates(self, client, project_slug, environment):
        """Test set_secret creates a new secret if it doesn't exist."""
        key = get_unique_key("SET_CREATE")
        self._track_key(key)
        value = "set_create_value"

        # set_secret should create if doesn't exist
        secret = client.set_secret(project_slug, environment, key, value)
        assert secret is not None
        assert secret.key == key

        # Verify it was created
        fetched = client.get_secret(project_slug, environment, key)
        assert fetched.value == value

    def test_set_secret_updates(self, client, project_slug, environment):
        """Test set_secret updates an existing secret."""
        key = get_unique_key("SET_UPDATE")
        self._track_key(key)
        initial_value = "set_initial"
        updated_value = "set_updated"

        # Create a secret
        client.create_secret(project_slug, environment, key, initial_value)

        # set_secret should update existing
        client.set_secret(project_slug, environment, key, updated_value)

        # Verify it was updated
        fetched = client.get_secret(project_slug, environment, key)
        assert fetched.value == updated_value

    def test_delete_secret(self, client, project_slug, environment):
        """Test deleting a secret."""
        key = get_unique_key("DELETE")
        value = "to_be_deleted"

        # Create a secret
        client.create_secret(project_slug, environment, key, value)

        # Delete the secret
        client.delete_secret(project_slug, environment, key)

        # Verify it was deleted
        with pytest.raises(KeyEnvError) as exc_info:
            client.get_secret(project_slug, environment, key)
        assert exc_info.value.status == 404

    def test_get_nonexistent_secret_returns_404(self, client, project_slug, environment):
        """Test that getting a nonexistent secret returns 404."""
        key = f"NONEXISTENT_{int(time.time() * 1000)}"

        with pytest.raises(KeyEnvError) as exc_info:
            client.get_secret(project_slug, environment, key)
        assert exc_info.value.status == 404


class TestBulkOperations:
    """Test bulk import operations."""

    @pytest.fixture(autouse=True)
    def setup_cleanup(self, client, project_slug, environment):
        """Track created secrets for cleanup."""
        self.created_keys: list[str] = []
        self.client = client
        self.project_slug = project_slug
        self.environment = environment
        yield
        # Cleanup
        for key in self.created_keys:
            try:
                client.delete_secret(project_slug, environment, key)
            except KeyEnvError:
                pass

    def _track_keys(self, keys: list[str]):
        """Track keys for cleanup."""
        self.created_keys.extend(keys)

    def test_bulk_import_creates_secrets(self, client, project_slug, environment):
        """Test bulk importing new secrets."""
        timestamp = int(time.time() * 1000)
        keys = [f"BULK_{timestamp}_1", f"BULK_{timestamp}_2", f"BULK_{timestamp}_3"]
        self._track_keys(keys)

        secrets = [
            BulkSecretItem(key=keys[0], value="bulk_value_1"),
            BulkSecretItem(key=keys[1], value="bulk_value_2"),
            BulkSecretItem(key=keys[2], value="bulk_value_3", description="With desc"),
        ]

        result = client.bulk_import(project_slug, environment, secrets)

        assert result.created == 3
        assert result.updated == 0
        assert result.skipped == 0

        # Verify secrets were created
        for i, key in enumerate(keys):
            fetched = client.get_secret(project_slug, environment, key)
            assert fetched.value == f"bulk_value_{i + 1}"

    def test_bulk_import_with_dict_format(self, client, project_slug, environment):
        """Test bulk import using dict format instead of BulkSecretItem."""
        timestamp = int(time.time() * 1000)
        keys = [f"BULK_DICT_{timestamp}_1", f"BULK_DICT_{timestamp}_2"]
        self._track_keys(keys)

        secrets = [
            {"key": keys[0], "value": "dict_value_1"},
            {"key": keys[1], "value": "dict_value_2"},
        ]

        result = client.bulk_import(project_slug, environment, secrets)

        assert result.created == 2
        assert result.updated == 0

    def test_bulk_import_with_overwrite(self, client, project_slug, environment):
        """Test bulk import with overwrite flag."""
        timestamp = int(time.time() * 1000)
        key = f"BULK_OVERWRITE_{timestamp}"
        self._track_keys([key])

        # Create initial secret
        client.create_secret(project_slug, environment, key, "initial")

        # Bulk import with overwrite
        secrets = [BulkSecretItem(key=key, value="overwritten")]
        result = client.bulk_import(project_slug, environment, secrets, overwrite=True)

        assert result.updated == 1
        assert result.created == 0

        # Verify value was updated
        fetched = client.get_secret(project_slug, environment, key)
        assert fetched.value == "overwritten"

    def test_bulk_import_skips_existing_without_overwrite(
        self, client, project_slug, environment
    ):
        """Test bulk import skips existing secrets when overwrite=False."""
        timestamp = int(time.time() * 1000)
        key = f"BULK_SKIP_{timestamp}"
        self._track_keys([key])

        # Create initial secret
        client.create_secret(project_slug, environment, key, "original")

        # Bulk import without overwrite
        secrets = [BulkSecretItem(key=key, value="should_be_skipped")]
        result = client.bulk_import(project_slug, environment, secrets, overwrite=False)

        assert result.skipped == 1
        assert result.created == 0
        assert result.updated == 0

        # Verify value was NOT updated
        fetched = client.get_secret(project_slug, environment, key)
        assert fetched.value == "original"


class TestSecretHistory:
    """Test secret history operations."""

    @pytest.fixture(autouse=True)
    def setup_cleanup(self, client, project_slug, environment):
        """Track created secrets for cleanup."""
        self.created_keys: list[str] = []
        self.client = client
        self.project_slug = project_slug
        self.environment = environment
        yield
        # Cleanup
        for key in self.created_keys:
            try:
                client.delete_secret(project_slug, environment, key)
            except KeyEnvError:
                pass

    def _track_key(self, key: str):
        """Track a key for cleanup."""
        self.created_keys.append(key)

    def test_get_secret_history(self, client, project_slug, environment):
        """Test getting secret version history."""
        key = get_unique_key("HISTORY")
        self._track_key(key)

        # Create a secret and update it to create history
        client.create_secret(project_slug, environment, key, "version_1")
        client.update_secret(project_slug, environment, key, "version_2")
        client.update_secret(project_slug, environment, key, "version_3")

        # Get history
        history = client.get_secret_history(project_slug, environment, key)

        assert isinstance(history, list)
        assert len(history) >= 3

        # History should be ordered by version
        versions = [h.version for h in history]
        assert versions == sorted(versions)


class TestUtilities:
    """Test utility methods."""

    @pytest.fixture(autouse=True)
    def setup_cleanup(self, client, project_slug, environment):
        """Track created secrets for cleanup."""
        self.created_keys: list[str] = []
        self.client = client
        self.project_slug = project_slug
        self.environment = environment
        yield
        # Cleanup
        for key in self.created_keys:
            try:
                client.delete_secret(project_slug, environment, key)
            except KeyEnvError:
                pass

    def _track_key(self, key: str):
        """Track a key for cleanup."""
        self.created_keys.append(key)

    def test_load_env(self, client, project_slug, environment):
        """Test loading secrets into os.environ."""
        key = get_unique_key("LOAD_ENV")
        self._track_key(key)
        value = "load_env_test_value"

        # Ensure the key is not in environ
        os.environ.pop(key, None)

        # Create a secret
        client.create_secret(project_slug, environment, key, value)

        # Load into environ
        count = client.load_env(project_slug, environment)

        assert count >= 1
        assert os.environ.get(key) == value

        # Cleanup environ
        os.environ.pop(key, None)

    def test_generate_env_file(self, client, project_slug, environment):
        """Test generating .env file content."""
        key = get_unique_key("ENV_FILE")
        self._track_key(key)
        value = "env_file_test"

        # Create a secret
        client.create_secret(project_slug, environment, key, value)

        # Generate env file content
        content = client.generate_env_file(project_slug, environment)

        assert isinstance(content, str)
        assert "# Generated by KeyEnv" in content
        assert f"# Environment: {environment}" in content
        assert f"{key}={value}" in content


class TestErrorHandling:
    """Test error handling."""

    def test_invalid_project_returns_error(self, client):
        """Test that accessing an invalid project returns an error."""
        with pytest.raises(KeyEnvError) as exc_info:
            client.get_project("nonexistent-project-12345")
        assert exc_info.value.status in (403, 404)

    def test_invalid_environment_returns_error(self, client, project_slug):
        """Test that accessing an invalid environment returns an error."""
        with pytest.raises(KeyEnvError) as exc_info:
            client.list_secrets(project_slug, "nonexistent-environment-12345")
        assert exc_info.value.status in (403, 404)


class TestInvalidToken:
    """Test behavior with invalid authentication."""

    def test_invalid_token_returns_401(self):
        """Test that an invalid token returns 401."""
        api_url = os.environ.get("KEYENV_API_URL")
        if not api_url:
            pytest.skip("KEYENV_API_URL not set")

        client = KeyEnv(token="invalid_token_12345", base_url=api_url)
        try:
            with pytest.raises(KeyEnvError) as exc_info:
                client.list_projects()
            assert exc_info.value.status == 401
        finally:
            client.close()
