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
