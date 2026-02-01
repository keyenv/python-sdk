"""Tests for KeyEnv client."""

import os
import pytest
import httpx
from unittest.mock import patch, MagicMock

from keyenv import KeyEnv, KeyEnvError
from keyenv.types import BulkSecretItem


class TestKeyEnvConstructor:
    """Tests for KeyEnv constructor."""

    def test_raises_if_token_not_provided(self):
        with pytest.raises(ValueError, match="KeyEnv token is required"):
            KeyEnv(token="")

    def test_creates_client_with_valid_token(self):
        client = KeyEnv(token="test-token")
        assert isinstance(client, KeyEnv)
        client.close()

    def test_accepts_custom_timeout(self):
        client = KeyEnv(token="test-token", timeout=5.0)
        assert isinstance(client, KeyEnv)
        client.close()

    def test_context_manager(self):
        with KeyEnv(token="test-token") as client:
            assert isinstance(client, KeyEnv)


class TestKeyEnvAPICalls:
    """Tests for KeyEnv API calls."""

    @pytest.fixture
    def client(self):
        client = KeyEnv(token="test-token")
        yield client
        client.close()

    @pytest.fixture
    def mock_response(self):
        def _mock_response(status_code=200, json_data=None):
            response = MagicMock(spec=httpx.Response)
            response.status_code = status_code
            response.is_success = 200 <= status_code < 300
            response.json.return_value = json_data or {}
            response.text = ""
            return response
        return _mock_response

    def test_get_current_user(self, client, mock_response):
        mock_user = {
            "id": "user-123",
            "email": "test@example.com",
            "name": "Test User",
        }

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_user)
            user = client.get_current_user()

            mock_request.assert_called_once_with("GET", "/api/v1/users/me", json=None)
            assert user.id == "user-123"
            assert user.email == "test@example.com"

    def test_get_current_user_service_token_with_project_ids(self, client, mock_response):
        mock_token = {
            "id": "token-123",
            "auth_type": "service_token",
            "team_id": "team-456",
            "project_ids": ["proj-1", "proj-2"],
            "scopes": ["read", "write"],
        }

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_token)
            user = client.get_current_user()

            assert user.id == "token-123"
            assert user.auth_type == "service_token"
            assert user.team_id == "team-456"
            assert user.project_ids == ["proj-1", "proj-2"]
            assert user.scopes == ["read", "write"]

    def test_list_projects(self, client, mock_response):
        mock_projects = {
            "projects": [
                {"id": "proj-1", "team_id": "team-1", "name": "Project 1", "slug": "project-1"},
                {"id": "proj-2", "team_id": "team-1", "name": "Project 2", "slug": "project-2"},
            ]
        }

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_projects)
            projects = client.list_projects()

            assert len(projects) == 2
            assert projects[0].id == "proj-1"
            assert projects[1].name == "Project 2"

    def test_export_secrets(self, client, mock_response):
        mock_secrets = {
            "secrets": [
                {"id": "s1", "environment_id": "env-1", "key": "DATABASE_URL", "value": "postgres://...", "type": "string", "version": 1},
                {"id": "s2", "environment_id": "env-1", "key": "API_KEY", "value": "sk_test_...", "type": "string", "version": 1},
            ]
        }

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_secrets)
            secrets = client.export_secrets("proj-1", "production")

            mock_request.assert_called_once_with(
                "GET",
                "/api/v1/projects/proj-1/environments/production/secrets/export",
                json=None
            )
            assert len(secrets) == 2
            assert secrets[0].key == "DATABASE_URL"
            assert secrets[0].value == "postgres://..."

    def test_export_secrets_as_dict(self, client, mock_response):
        mock_secrets = {
            "secrets": [
                {"id": "s1", "environment_id": "env-1", "key": "DATABASE_URL", "value": "postgres://localhost", "type": "string", "version": 1},
                {"id": "s2", "environment_id": "env-1", "key": "API_KEY", "value": "sk_test_123", "type": "string", "version": 1},
            ]
        }

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_secrets)
            env = client.export_secrets_as_dict("proj-1", "production")

            assert env == {
                "DATABASE_URL": "postgres://localhost",
                "API_KEY": "sk_test_123",
            }

    def test_set_secret_creates_on_404(self, client, mock_response):
        mock_secret = {"id": "s1", "environment_id": "env-1", "key": "NEW_KEY", "type": "string", "version": 1}

        with patch.object(client._client, "request") as mock_request:
            # First call (update) returns 404
            error_response = mock_response(404)
            error_response.json.return_value = {"error": "Not found"}
            # Second call (create) succeeds
            success_response = mock_response(201, {"secret": mock_secret})

            mock_request.side_effect = [error_response, success_response]

            secret = client.set_secret("proj-1", "production", "NEW_KEY", "new-value")

            assert mock_request.call_count == 2
            assert secret.key == "NEW_KEY"

    def test_handles_401_error(self, client, mock_response):
        with patch.object(client._client, "request") as mock_request:
            error_response = mock_response(401)
            error_response.json.return_value = {"error": "Invalid token"}
            mock_request.return_value = error_response

            with pytest.raises(KeyEnvError) as exc_info:
                client.get_current_user()

            assert exc_info.value.status == 401
            assert "Invalid token" in str(exc_info.value.message)

    def test_handles_403_error(self, client, mock_response):
        with patch.object(client._client, "request") as mock_request:
            error_response = mock_response(403)
            error_response.json.return_value = {"error": "Access denied"}
            mock_request.return_value = error_response

            with pytest.raises(KeyEnvError):
                client.list_projects()

    def test_handles_network_error(self, client):
        with patch.object(client._client, "request") as mock_request:
            mock_request.side_effect = httpx.RequestError("Network error")

            with pytest.raises(KeyEnvError):
                client.get_current_user()

    def test_handles_timeout(self, client):
        with patch.object(client._client, "request") as mock_request:
            mock_request.side_effect = httpx.TimeoutException("Timeout")

            with pytest.raises(KeyEnvError) as exc_info:
                client.get_current_user()

            assert exc_info.value.status == 408

    def test_handles_204_no_content(self, client, mock_response):
        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(204)
            result = client.delete_secret("proj-1", "production", "KEY")
            assert result is None

    def test_bulk_import(self, client, mock_response):
        mock_result = {"created": 2, "updated": 0, "skipped": 0}

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_result)

            result = client.bulk_import(
                "proj-1",
                "development",
                [
                    BulkSecretItem(key="KEY1", value="value1"),
                    {"key": "KEY2", "value": "value2"},
                ],
                overwrite=True,
            )

            mock_request.assert_called_once()
            call_args = mock_request.call_args
            assert call_args[0][0] == "POST"
            assert "/bulk" in call_args[0][1]
            assert result.created == 2
            assert result.updated == 0

    def test_get_project(self, client, mock_response):
        mock_project = {
            "id": "proj-1",
            "team_id": "team-1",
            "name": "My Project",
            "slug": "my-project",
            "created_at": "2024-01-01T00:00:00Z",
            "environments": [
                {"id": "env-1", "project_id": "proj-1", "name": "development", "created_at": "2024-01-01T00:00:00Z"},
                {"id": "env-2", "project_id": "proj-1", "name": "production", "created_at": "2024-01-01T00:00:00Z"},
            ],
        }

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_project)
            project = client.get_project("proj-1")

            mock_request.assert_called_once_with("GET", "/api/v1/projects/proj-1", json=None)
            assert project.id == "proj-1"
            assert project.name == "My Project"
            assert len(project.environments) == 2

    def test_create_project(self, client, mock_response):
        mock_project = {
            "id": "proj-new",
            "team_id": "team-1",
            "name": "New Project",
            "slug": "new-project",
            "created_at": "2024-01-01T00:00:00Z",
        }

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(201, mock_project)
            project = client.create_project("team-1", "New Project")

            mock_request.assert_called_once_with(
                "POST", "/api/v1/projects", json={"team_id": "team-1", "name": "New Project"}
            )
            assert project.id == "proj-new"
            assert project.name == "New Project"

    def test_delete_project(self, client, mock_response):
        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(204)
            result = client.delete_project("proj-1")

            mock_request.assert_called_once_with("DELETE", "/api/v1/projects/proj-1", json=None)
            assert result is None

    def test_list_environments(self, client, mock_response):
        mock_environments = {
            "environments": [
                {"id": "env-1", "project_id": "proj-1", "name": "development", "created_at": "2024-01-01T00:00:00Z"},
                {"id": "env-2", "project_id": "proj-1", "name": "staging", "created_at": "2024-01-01T00:00:00Z"},
                {"id": "env-3", "project_id": "proj-1", "name": "production", "created_at": "2024-01-01T00:00:00Z"},
            ]
        }

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_environments)
            environments = client.list_environments("proj-1")

            mock_request.assert_called_once_with("GET", "/api/v1/projects/proj-1/environments", json=None)
            assert len(environments) == 3
            assert environments[0].name == "development"

    def test_create_environment(self, client, mock_response):
        mock_environment = {
            "id": "env-new",
            "project_id": "proj-1",
            "name": "staging",
            "inherits_from": "development",
            "created_at": "2024-01-01T00:00:00Z",
        }

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(201, mock_environment)
            environment = client.create_environment("proj-1", "staging", "development")

            mock_request.assert_called_once_with(
                "POST",
                "/api/v1/projects/proj-1/environments",
                json={"name": "staging", "inherits_from": "development"},
            )
            assert environment.name == "staging"
            assert environment.inherits_from == "development"

    def test_delete_environment(self, client, mock_response):
        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(204)
            result = client.delete_environment("proj-1", "staging")

            mock_request.assert_called_once_with(
                "DELETE", "/api/v1/projects/proj-1/environments/staging", json=None
            )
            assert result is None

    def test_list_secrets(self, client, mock_response):
        mock_secrets = {
            "secrets": [
                {"id": "s1", "environment_id": "env-1", "key": "DATABASE_URL", "type": "string", "version": 1, "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"},
                {"id": "s2", "environment_id": "env-1", "key": "API_KEY", "type": "string", "version": 1, "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"},
            ]
        }

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_secrets)
            secrets = client.list_secrets("proj-1", "production")

            mock_request.assert_called_once_with(
                "GET", "/api/v1/projects/proj-1/environments/production/secrets", json=None
            )
            assert len(secrets) == 2
            assert secrets[0].key == "DATABASE_URL"

    def test_get_secret(self, client, mock_response):
        mock_secret = {
            "secret": {
                "id": "s1",
                "environment_id": "env-1",
                "key": "DATABASE_URL",
                "value": "postgres://localhost:5432/mydb",
                "type": "string",
                "version": 1,
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z",
            }
        }

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_secret)
            secret = client.get_secret("proj-1", "production", "DATABASE_URL")

            mock_request.assert_called_once_with(
                "GET", "/api/v1/projects/proj-1/environments/production/secrets/DATABASE_URL", json=None
            )
            assert secret.key == "DATABASE_URL"
            assert secret.value == "postgres://localhost:5432/mydb"

    def test_create_secret(self, client, mock_response):
        mock_secret = {
            "secret": {
                "id": "s-new",
                "environment_id": "env-1",
                "key": "NEW_SECRET",
                "type": "string",
                "description": "A new secret",
                "version": 1,
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z",
            }
        }

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(201, mock_secret)
            secret = client.create_secret("proj-1", "production", "NEW_SECRET", "secret-value", "A new secret")

            mock_request.assert_called_once_with(
                "POST",
                "/api/v1/projects/proj-1/environments/production/secrets",
                json={"key": "NEW_SECRET", "value": "secret-value", "description": "A new secret"},
            )
            assert secret.key == "NEW_SECRET"

    def test_update_secret(self, client, mock_response):
        mock_secret = {
            "secret": {
                "id": "s1",
                "environment_id": "env-1",
                "key": "DATABASE_URL",
                "type": "string",
                "version": 2,
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-02T00:00:00Z",
            }
        }

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_secret)
            secret = client.update_secret("proj-1", "production", "DATABASE_URL", "postgres://newhost:5432/mydb")

            mock_request.assert_called_once_with(
                "PUT",
                "/api/v1/projects/proj-1/environments/production/secrets/DATABASE_URL",
                json={"value": "postgres://newhost:5432/mydb"},
            )
            assert secret.version == 2

    def test_get_secret_history(self, client, mock_response):
        mock_history = {
            "history": [
                {"id": "h1", "secret_id": "s1", "value": "old-value", "version": 1, "changed_by": "user-1", "changed_at": "2024-01-01T00:00:00Z"},
                {"id": "h2", "secret_id": "s1", "value": "new-value", "version": 2, "changed_by": "user-1", "changed_at": "2024-01-02T00:00:00Z"},
            ]
        }

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_history)
            history = client.get_secret_history("proj-1", "production", "DATABASE_URL")

            mock_request.assert_called_once_with(
                "GET",
                "/api/v1/projects/proj-1/environments/production/secrets/DATABASE_URL/history",
                json=None,
            )
            assert len(history) == 2
            assert history[0].version == 1
            assert history[1].version == 2


class TestGenerateEnvFile:
    """Tests for generate_env_file method."""

    @pytest.fixture
    def client(self):
        client = KeyEnv(token="test-token")
        yield client
        client.close()

    @pytest.fixture
    def mock_response(self):
        def _mock_response(status_code=200, json_data=None):
            response = MagicMock(spec=httpx.Response)
            response.status_code = status_code
            response.is_success = 200 <= status_code < 300
            response.json.return_value = json_data or {}
            response.text = ""
            return response
        return _mock_response

    def test_generates_valid_env_content(self, client, mock_response):
        mock_secrets = {
            "secrets": [
                {"id": "s1", "environment_id": "env-1", "key": "SIMPLE", "value": "value", "type": "string", "version": 1},
                {"id": "s2", "environment_id": "env-1", "key": "WITH_SPACES", "value": "hello world", "type": "string", "version": 1},
                {"id": "s3", "environment_id": "env-1", "key": "WITH_QUOTES", "value": 'say "hello"', "type": "string", "version": 1},
            ]
        }

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_secrets)
            content = client.generate_env_file("proj-1", "production")

            assert "# Generated by KeyEnv" in content
            assert "SIMPLE=value" in content
            assert 'WITH_SPACES="hello world"' in content
            assert 'WITH_QUOTES="say \\"hello\\""' in content


class TestGenerateEnvFileDollarEscaping:
    """Tests for $ escaping in generate_env_file."""

    @pytest.fixture
    def client(self):
        client = KeyEnv(token="test-token")
        yield client
        client.close()

    @pytest.fixture
    def mock_response(self):
        def _mock_response(status_code=200, json_data=None):
            response = MagicMock(spec=httpx.Response)
            response.status_code = status_code
            response.is_success = 200 <= status_code < 300
            response.json.return_value = json_data or {}
            response.text = ""
            return response
        return _mock_response

    def test_escapes_dollar_signs(self, client, mock_response):
        mock_secrets = {
            "secrets": [
                {"id": "s1", "environment_id": "env-1", "key": "DOLLAR_VAR", "value": "price=$100", "type": "string", "version": 1},
                {"id": "s2", "environment_id": "env-1", "key": "SIMPLE", "value": "no_special", "type": "string", "version": 1},
            ]
        }

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_secrets)
            content = client.generate_env_file("proj-1", "production")

            assert 'DOLLAR_VAR="price=\\$100"' in content
            assert "SIMPLE=no_special" in content


class TestCacheIsolation:
    """Tests that different client instances do not share cache."""

    @pytest.fixture
    def mock_response(self):
        def _mock_response(status_code=200, json_data=None):
            response = MagicMock(spec=httpx.Response)
            response.status_code = status_code
            response.is_success = 200 <= status_code < 300
            response.json.return_value = json_data or {}
            response.text = ""
            return response
        return _mock_response

    def test_different_instances_have_separate_caches(self, mock_response):
        mock_secrets_1 = {
            "secrets": [{"id": "s1", "environment_id": "env-1", "key": "KEY1", "value": "value_from_client1", "type": "string", "version": 1}]
        }
        mock_secrets_2 = {
            "secrets": [{"id": "s2", "environment_id": "env-1", "key": "KEY1", "value": "value_from_client2", "type": "string", "version": 1}]
        }

        client1 = KeyEnv(token="token-1", cache_ttl=300)
        client2 = KeyEnv(token="token-2", cache_ttl=300)

        with patch.object(client1._client, "request") as mock_request1:
            mock_request1.return_value = mock_response(200, mock_secrets_1)
            secrets1 = client1.export_secrets("proj-1", "production")

        with patch.object(client2._client, "request") as mock_request2:
            mock_request2.return_value = mock_response(200, mock_secrets_2)
            secrets2 = client2.export_secrets("proj-1", "production")

        assert secrets1[0].value == "value_from_client1"
        assert secrets2[0].value == "value_from_client2"

        # Clearing client1's cache should not affect client2
        client1.clear_cache()
        assert len(client1._secrets_cache) == 0
        assert len(client2._secrets_cache) == 1

        client1.close()
        client2.close()


class TestLoadEnv:
    """Tests for load_env method."""

    @pytest.fixture
    def client(self):
        client = KeyEnv(token="test-token")
        yield client
        client.close()

    @pytest.fixture
    def mock_response(self):
        def _mock_response(status_code=200, json_data=None):
            response = MagicMock(spec=httpx.Response)
            response.status_code = status_code
            response.is_success = 200 <= status_code < 300
            response.json.return_value = json_data or {}
            response.text = ""
            return response
        return _mock_response

    def test_loads_secrets_into_environ(self, client, mock_response):
        mock_secrets = {
            "secrets": [
                {"id": "s1", "environment_id": "env-1", "key": "TEST_VAR_1", "value": "test_value_1", "type": "string", "version": 1},
                {"id": "s2", "environment_id": "env-1", "key": "TEST_VAR_2", "value": "test_value_2", "type": "string", "version": 1},
            ]
        }

        # Clean up any existing env vars
        os.environ.pop("TEST_VAR_1", None)
        os.environ.pop("TEST_VAR_2", None)

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_secrets)
            count = client.load_env("proj-1", "production")

            assert count == 2
            assert os.environ.get("TEST_VAR_1") == "test_value_1"
            assert os.environ.get("TEST_VAR_2") == "test_value_2"

        # Clean up
        os.environ.pop("TEST_VAR_1", None)
        os.environ.pop("TEST_VAR_2", None)


class TestKeyEnvError:
    """Tests for KeyEnvError."""

    def test_creates_error_with_all_properties(self):
        error = KeyEnvError("Test error", 404, "not_found", {"id": "123"})

        assert error.message == "Test error"
        assert error.status == 404
        assert error.code == "not_found"
        assert error.details == {"id": "123"}

    def test_str_representation_with_status(self):
        error = KeyEnvError("Test error", 404)
        assert str(error) == "KeyEnvError(404): Test error"

    def test_str_representation_without_status(self):
        error = KeyEnvError("Test error")
        assert str(error) == "KeyEnvError: Test error"


class TestCaching:
    """Tests for secrets caching."""

    @pytest.fixture
    def mock_response(self):
        def _mock_response(status_code=200, json_data=None):
            response = MagicMock(spec=httpx.Response)
            response.status_code = status_code
            response.is_success = 200 <= status_code < 300
            response.json.return_value = json_data or {}
            response.text = ""
            return response
        return _mock_response

    @pytest.fixture(autouse=True)
    def clear_cache(self):
        """Clear the cache before and after each test."""
        yield

    def test_cache_disabled_by_default(self, mock_response):
        """Test that caching is disabled when cache_ttl is 0."""
        mock_secrets = {
            "secrets": [
                {"id": "s1", "environment_id": "env-1", "key": "KEY1", "value": "value1", "type": "string", "version": 1},
                {"id": "s2", "environment_id": "env-1", "key": "KEY2", "value": "value2", "type": "string", "version": 1},
            ]
        }

        client = KeyEnv(token="test-token")

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_secrets)

            # First call
            secrets1 = client.export_secrets("proj-1", "production")
            # Second call - should hit API again (no cache)
            secrets2 = client.export_secrets("proj-1", "production")

            # API should be called twice
            assert mock_request.call_count == 2
            assert len(secrets1) == 2
            assert len(secrets2) == 2

        client.close()

    def test_cache_hit_returns_cached_data(self, mock_response):
        """Test that cached data is returned on cache hit."""
        mock_secrets = {
            "secrets": [
                {"id": "s1", "environment_id": "env-1", "key": "KEY1", "value": "value1", "type": "string", "version": 1},
            ]
        }

        client = KeyEnv(token="test-token", cache_ttl=300)  # 5 minutes

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_secrets)

            # First call - populates cache
            secrets1 = client.export_secrets("proj-1", "production")
            # Second call - should use cache
            secrets2 = client.export_secrets("proj-1", "production")

            # API should be called only once
            assert mock_request.call_count == 1
            assert secrets1 == secrets2

        client.close()

    def test_cache_expiration(self, mock_response):
        """Test that cache expires after TTL."""
        import time as time_module

        mock_secrets_v1 = {
            "secrets": [{"id": "s1", "environment_id": "env-1", "key": "KEY1", "value": "v1", "type": "string", "version": 1}]
        }
        mock_secrets_v2 = {
            "secrets": [{"id": "s1", "environment_id": "env-1", "key": "KEY1", "value": "v2", "type": "string", "version": 2}]
        }

        client = KeyEnv(token="test-token", cache_ttl=1)  # 1 second TTL

        with patch.object(client._client, "request") as mock_request:
            # First call returns v1
            mock_request.return_value = mock_response(200, mock_secrets_v1)
            secrets1 = client.export_secrets("proj-1", "production")
            assert secrets1[0].value == "v1"

            # Second call (within TTL) - returns cached v1
            secrets2 = client.export_secrets("proj-1", "production")
            assert secrets2[0].value == "v1"
            assert mock_request.call_count == 1

            # Wait for cache to expire
            time_module.sleep(1.1)

            # Third call (after TTL) - should fetch new data
            mock_request.return_value = mock_response(200, mock_secrets_v2)
            secrets3 = client.export_secrets("proj-1", "production")
            assert secrets3[0].value == "v2"
            assert mock_request.call_count == 2

        client.close()

    def test_clear_cache_specific_environment(self, mock_response):
        """Test clearing cache for a specific project/environment."""
        mock_secrets = {
            "secrets": [{"id": "s1", "environment_id": "env-1", "key": "KEY1", "value": "value1", "type": "string", "version": 1}]
        }

        client = KeyEnv(token="test-token", cache_ttl=300)

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_secrets)

            # Populate cache
            client.export_secrets("proj-1", "production")
            client.export_secrets("proj-1", "staging")
            assert len(client._secrets_cache) == 2

            # Clear specific environment
            client.clear_cache("proj-1", "production")
            assert len(client._secrets_cache) == 1
            assert "proj-1:staging" in client._secrets_cache

        client.close()

    def test_clear_cache_entire_project(self, mock_response):
        """Test clearing cache for an entire project."""
        mock_secrets = {
            "secrets": [{"id": "s1", "environment_id": "env-1", "key": "KEY1", "value": "value1", "type": "string", "version": 1}]
        }

        client = KeyEnv(token="test-token", cache_ttl=300)

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_secrets)

            # Populate cache for multiple projects
            client.export_secrets("proj-1", "production")
            client.export_secrets("proj-1", "staging")
            client.export_secrets("proj-2", "production")
            assert len(client._secrets_cache) == 3

            # Clear entire project
            client.clear_cache("proj-1")
            assert len(client._secrets_cache) == 1
            assert "proj-2:production" in client._secrets_cache

        client.close()

    def test_clear_cache_all(self, mock_response):
        """Test clearing entire cache."""
        mock_secrets = {
            "secrets": [{"id": "s1", "environment_id": "env-1", "key": "KEY1", "value": "value1", "type": "string", "version": 1}]
        }

        client = KeyEnv(token="test-token", cache_ttl=300)

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_secrets)

            # Populate cache
            client.export_secrets("proj-1", "production")
            client.export_secrets("proj-2", "staging")
            assert len(client._secrets_cache) == 2

            # Clear all
            client.clear_cache()
            assert len(client._secrets_cache) == 0

        client.close()

    def test_cache_ttl_from_env_var(self, mock_response):
        """Test that cache TTL can be set via environment variable."""
        mock_secrets = {
            "secrets": [{"id": "s1", "environment_id": "env-1", "key": "KEY1", "value": "value1", "type": "string", "version": 1}]
        }

        with patch.dict(os.environ, {"KEYENV_CACHE_TTL": "60"}):
            client = KeyEnv(token="test-token")
            assert client._cache_ttl == 60

            with patch.object(client._client, "request") as mock_request:
                mock_request.return_value = mock_response(200, mock_secrets)

                # Cache should be enabled
                client.export_secrets("proj-1", "production")
                client.export_secrets("proj-1", "production")
                assert mock_request.call_count == 1

            client.close()

    def test_constructor_cache_ttl_overrides_env_var(self, mock_response):
        """Test that constructor cache_ttl overrides env var."""
        with patch.dict(os.environ, {"KEYENV_CACHE_TTL": "60"}):
            client = KeyEnv(token="test-token", cache_ttl=120)
            assert client._cache_ttl == 120
            client.close()

    def test_cache_key_isolation(self, mock_response):
        """Test that different project/environment combos have isolated caches."""
        mock_secrets_prod = {
            "secrets": [{"id": "s1", "environment_id": "env-1", "key": "KEY1", "value": "prod_value", "type": "string", "version": 1}]
        }
        mock_secrets_stag = {
            "secrets": [{"id": "s2", "environment_id": "env-2", "key": "KEY1", "value": "stag_value", "type": "string", "version": 1}]
        }

        client = KeyEnv(token="test-token", cache_ttl=300)

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_secrets_prod)
            secrets_prod = client.export_secrets("proj-1", "production")

            mock_request.return_value = mock_response(200, mock_secrets_stag)
            secrets_stag = client.export_secrets("proj-1", "staging")

            # Values should be different (isolated caches)
            assert secrets_prod[0].value == "prod_value"
            assert secrets_stag[0].value == "stag_value"
            assert mock_request.call_count == 2

        client.close()
