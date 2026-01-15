"""Tests for KeyEnv permission methods and types."""

import pytest
import httpx
from unittest.mock import patch, MagicMock

from keyenv import KeyEnv, KeyEnvError, EnvironmentPermission, MyPermission, ProjectDefault


class TestListPermissions:
    """Tests for list_permissions method."""

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

    def test_list_permissions_success(self, client, mock_response):
        mock_permissions = {
            "permissions": [
                {
                    "id": "perm_1",
                    "environment_id": "env_1",
                    "user_id": "user_1",
                    "role": "write",
                    "user_email": "user1@example.com",
                    "user_name": "User One",
                    "granted_by": "admin_1",
                    "created_at": "2024-01-01T00:00:00Z",
                    "updated_at": "2024-01-02T00:00:00Z",
                },
                {
                    "id": "perm_2",
                    "environment_id": "env_1",
                    "user_id": "user_2",
                    "role": "read",
                    "user_email": "user2@example.com",
                    "user_name": "User Two",
                    "granted_by": "admin_1",
                    "created_at": "2024-01-01T00:00:00Z",
                    "updated_at": "2024-01-01T00:00:00Z",
                },
            ]
        }

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_permissions)
            result = client.list_permissions("proj_1", "development")

            mock_request.assert_called_once_with(
                "GET",
                "/api/v1/projects/proj_1/environments/development/permissions",
                json=None,
            )
            assert len(result) == 2
            assert isinstance(result[0], EnvironmentPermission)
            assert result[0].id == "perm_1"
            assert result[0].role == "write"
            assert result[0].user_email == "user1@example.com"
            assert result[1].role == "read"

    def test_list_permissions_empty(self, client, mock_response):
        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, {"permissions": []})
            result = client.list_permissions("proj_1", "development")

            assert result == []

    def test_list_permissions_missing_permissions_key(self, client, mock_response):
        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, {})
            result = client.list_permissions("proj_1", "development")

            assert result == []

    def test_list_permissions_unauthorized(self, client, mock_response):
        with patch.object(client._client, "request") as mock_request:
            error_response = mock_response(401)
            error_response.json.return_value = {"error": "Invalid token"}
            mock_request.return_value = error_response

            with pytest.raises(KeyEnvError) as exc:
                client.list_permissions("proj_1", "development")

            assert exc.value.status == 401
            assert "Invalid token" in exc.value.message

    def test_list_permissions_forbidden(self, client, mock_response):
        with patch.object(client._client, "request") as mock_request:
            error_response = mock_response(403)
            error_response.json.return_value = {"error": "Access denied"}
            mock_request.return_value = error_response

            with pytest.raises(KeyEnvError) as exc:
                client.list_permissions("proj_1", "development")

            assert exc.value.status == 403

    def test_list_permissions_not_found(self, client, mock_response):
        with patch.object(client._client, "request") as mock_request:
            error_response = mock_response(404)
            error_response.json.return_value = {"error": "Project or environment not found"}
            mock_request.return_value = error_response

            with pytest.raises(KeyEnvError) as exc:
                client.list_permissions("nonexistent", "development")

            assert exc.value.status == 404


class TestSetPermission:
    """Tests for set_permission method."""

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

    def test_set_permission_write_role(self, client, mock_response):
        mock_permission = {
            "id": "perm_1",
            "environment_id": "env_1",
            "user_id": "user_1",
            "role": "write",
            "user_email": "user@example.com",
            "user_name": "Test User",
            "granted_by": "admin_1",
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
        }

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_permission)
            result = client.set_permission("proj_1", "development", "user_1", "write")

            mock_request.assert_called_once_with(
                "PUT",
                "/api/v1/projects/proj_1/environments/development/permissions/user_1",
                json={"role": "write"},
            )
            assert isinstance(result, EnvironmentPermission)
            assert result.role == "write"
            assert result.user_id == "user_1"

    def test_set_permission_read_role(self, client, mock_response):
        mock_permission = {
            "id": "perm_2",
            "environment_id": "env_1",
            "user_id": "user_2",
            "role": "read",
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
        }

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_permission)
            result = client.set_permission("proj_1", "production", "user_2", "read")

            mock_request.assert_called_once_with(
                "PUT",
                "/api/v1/projects/proj_1/environments/production/permissions/user_2",
                json={"role": "read"},
            )
            assert result.role == "read"

    def test_set_permission_admin_role(self, client, mock_response):
        mock_permission = {
            "id": "perm_3",
            "environment_id": "env_1",
            "user_id": "user_3",
            "role": "admin",
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
        }

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_permission)
            result = client.set_permission("proj_1", "staging", "user_3", "admin")

            assert result.role == "admin"

    def test_set_permission_none_role(self, client, mock_response):
        mock_permission = {
            "id": "perm_4",
            "environment_id": "env_1",
            "user_id": "user_4",
            "role": "none",
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
        }

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_permission)
            result = client.set_permission("proj_1", "development", "user_4", "none")

            assert result.role == "none"

    def test_set_permission_unauthorized(self, client, mock_response):
        with patch.object(client._client, "request") as mock_request:
            error_response = mock_response(401)
            error_response.json.return_value = {"error": "Invalid token"}
            mock_request.return_value = error_response

            with pytest.raises(KeyEnvError) as exc:
                client.set_permission("proj_1", "development", "user_1", "write")

            assert exc.value.status == 401

    def test_set_permission_forbidden(self, client, mock_response):
        with patch.object(client._client, "request") as mock_request:
            error_response = mock_response(403)
            error_response.json.return_value = {"error": "You don't have permission to modify permissions"}
            mock_request.return_value = error_response

            with pytest.raises(KeyEnvError) as exc:
                client.set_permission("proj_1", "production", "user_1", "admin")

            assert exc.value.status == 403


class TestDeletePermission:
    """Tests for delete_permission method."""

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

    def test_delete_permission_success(self, client, mock_response):
        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(204)
            result = client.delete_permission("proj_1", "development", "user_1")

            mock_request.assert_called_once_with(
                "DELETE",
                "/api/v1/projects/proj_1/environments/development/permissions/user_1",
                json=None,
            )
            assert result is None

    def test_delete_permission_not_found(self, client, mock_response):
        with patch.object(client._client, "request") as mock_request:
            error_response = mock_response(404)
            error_response.json.return_value = {"error": "Permission not found"}
            mock_request.return_value = error_response

            with pytest.raises(KeyEnvError) as exc:
                client.delete_permission("proj_1", "development", "nonexistent_user")

            assert exc.value.status == 404

    def test_delete_permission_forbidden(self, client, mock_response):
        with patch.object(client._client, "request") as mock_request:
            error_response = mock_response(403)
            error_response.json.return_value = {"error": "Cannot delete your own permission"}
            mock_request.return_value = error_response

            with pytest.raises(KeyEnvError) as exc:
                client.delete_permission("proj_1", "production", "current_user")

            assert exc.value.status == 403


class TestBulkSetPermissions:
    """Tests for bulk_set_permissions method."""

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

    def test_bulk_set_permissions_success(self, client, mock_response):
        mock_permissions = {
            "permissions": [
                {
                    "id": "perm_1",
                    "environment_id": "env_1",
                    "user_id": "user_1",
                    "role": "write",
                    "created_at": "2024-01-01T00:00:00Z",
                    "updated_at": "2024-01-01T00:00:00Z",
                },
                {
                    "id": "perm_2",
                    "environment_id": "env_1",
                    "user_id": "user_2",
                    "role": "read",
                    "created_at": "2024-01-01T00:00:00Z",
                    "updated_at": "2024-01-01T00:00:00Z",
                },
            ]
        }

        permissions_to_set = [
            {"user_id": "user_1", "role": "write"},
            {"user_id": "user_2", "role": "read"},
        ]

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_permissions)
            result = client.bulk_set_permissions("proj_1", "development", permissions_to_set)

            mock_request.assert_called_once_with(
                "PUT",
                "/api/v1/projects/proj_1/environments/development/permissions",
                json={"permissions": permissions_to_set},
            )
            assert len(result) == 2
            assert all(isinstance(p, EnvironmentPermission) for p in result)
            assert result[0].role == "write"
            assert result[1].role == "read"

    def test_bulk_set_permissions_empty_list(self, client, mock_response):
        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, {"permissions": []})
            result = client.bulk_set_permissions("proj_1", "development", [])

            mock_request.assert_called_once_with(
                "PUT",
                "/api/v1/projects/proj_1/environments/development/permissions",
                json={"permissions": []},
            )
            assert result == []

    def test_bulk_set_permissions_mixed_roles(self, client, mock_response):
        mock_permissions = {
            "permissions": [
                {"id": "perm_1", "environment_id": "env_1", "user_id": "user_1", "role": "admin", "created_at": "", "updated_at": ""},
                {"id": "perm_2", "environment_id": "env_1", "user_id": "user_2", "role": "write", "created_at": "", "updated_at": ""},
                {"id": "perm_3", "environment_id": "env_1", "user_id": "user_3", "role": "read", "created_at": "", "updated_at": ""},
                {"id": "perm_4", "environment_id": "env_1", "user_id": "user_4", "role": "none", "created_at": "", "updated_at": ""},
            ]
        }

        permissions_to_set = [
            {"user_id": "user_1", "role": "admin"},
            {"user_id": "user_2", "role": "write"},
            {"user_id": "user_3", "role": "read"},
            {"user_id": "user_4", "role": "none"},
        ]

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_permissions)
            result = client.bulk_set_permissions("proj_1", "production", permissions_to_set)

            assert len(result) == 4
            assert result[0].role == "admin"
            assert result[1].role == "write"
            assert result[2].role == "read"
            assert result[3].role == "none"

    def test_bulk_set_permissions_forbidden(self, client, mock_response):
        with patch.object(client._client, "request") as mock_request:
            error_response = mock_response(403)
            error_response.json.return_value = {"error": "Forbidden"}
            mock_request.return_value = error_response

            with pytest.raises(KeyEnvError) as exc:
                client.bulk_set_permissions("proj_1", "development", [{"user_id": "user_1", "role": "write"}])

            assert exc.value.status == 403


class TestGetMyPermissions:
    """Tests for get_my_permissions method."""

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

    def test_get_my_permissions_returns_tuple(self, client, mock_response):
        mock_data = {
            "permissions": [
                {
                    "environment_id": "env_1",
                    "environment_name": "development",
                    "role": "write",
                    "can_read": True,
                    "can_write": True,
                    "can_admin": False,
                },
                {
                    "environment_id": "env_2",
                    "environment_name": "production",
                    "role": "read",
                    "can_read": True,
                    "can_write": False,
                    "can_admin": False,
                },
            ],
            "is_team_admin": True,
        }

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_data)
            permissions, is_admin = client.get_my_permissions("proj_1")

            mock_request.assert_called_once_with(
                "GET",
                "/api/v1/projects/proj_1/my-permissions",
                json=None,
            )
            assert len(permissions) == 2
            assert isinstance(permissions[0], MyPermission)
            assert permissions[0].environment_name == "development"
            assert permissions[0].role == "write"
            assert permissions[0].can_read is True
            assert permissions[0].can_write is True
            assert permissions[0].can_admin is False
            assert is_admin is True

    def test_get_my_permissions_not_team_admin(self, client, mock_response):
        mock_data = {
            "permissions": [
                {
                    "environment_id": "env_1",
                    "environment_name": "development",
                    "role": "read",
                    "can_read": True,
                    "can_write": False,
                    "can_admin": False,
                },
            ],
            "is_team_admin": False,
        }

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_data)
            permissions, is_admin = client.get_my_permissions("proj_1")

            assert is_admin is False
            assert permissions[0].can_write is False

    def test_get_my_permissions_empty_permissions(self, client, mock_response):
        mock_data = {
            "permissions": [],
            "is_team_admin": False,
        }

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_data)
            permissions, is_admin = client.get_my_permissions("proj_1")

            assert permissions == []
            assert is_admin is False

    def test_get_my_permissions_missing_is_team_admin(self, client, mock_response):
        mock_data = {
            "permissions": [
                {
                    "environment_id": "env_1",
                    "environment_name": "development",
                    "role": "admin",
                    "can_read": True,
                    "can_write": True,
                    "can_admin": True,
                },
            ],
        }

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_data)
            permissions, is_admin = client.get_my_permissions("proj_1")

            assert len(permissions) == 1
            # Should default to False when is_team_admin is missing
            assert is_admin is False

    def test_get_my_permissions_admin_role(self, client, mock_response):
        mock_data = {
            "permissions": [
                {
                    "environment_id": "env_1",
                    "environment_name": "production",
                    "role": "admin",
                    "can_read": True,
                    "can_write": True,
                    "can_admin": True,
                },
            ],
            "is_team_admin": False,
        }

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_data)
            permissions, is_admin = client.get_my_permissions("proj_1")

            assert permissions[0].role == "admin"
            assert permissions[0].can_admin is True


class TestGetProjectDefaults:
    """Tests for get_project_defaults method."""

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

    def test_get_project_defaults_success(self, client, mock_response):
        mock_defaults = {
            "defaults": [
                {
                    "id": "def_1",
                    "project_id": "proj_1",
                    "environment_name": "development",
                    "default_role": "write",
                    "created_at": "2024-01-01T00:00:00Z",
                },
                {
                    "id": "def_2",
                    "project_id": "proj_1",
                    "environment_name": "production",
                    "default_role": "read",
                    "created_at": "2024-01-01T00:00:00Z",
                },
            ]
        }

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_defaults)
            result = client.get_project_defaults("proj_1")

            mock_request.assert_called_once_with(
                "GET",
                "/api/v1/projects/proj_1/permissions/defaults",
                json=None,
            )
            assert len(result) == 2
            assert isinstance(result[0], ProjectDefault)
            assert result[0].environment_name == "development"
            assert result[0].default_role == "write"
            assert result[1].default_role == "read"

    def test_get_project_defaults_empty(self, client, mock_response):
        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, {"defaults": []})
            result = client.get_project_defaults("proj_1")

            assert result == []

    def test_get_project_defaults_missing_key(self, client, mock_response):
        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, {})
            result = client.get_project_defaults("proj_1")

            assert result == []

    def test_get_project_defaults_not_found(self, client, mock_response):
        with patch.object(client._client, "request") as mock_request:
            error_response = mock_response(404)
            error_response.json.return_value = {"error": "Project not found"}
            mock_request.return_value = error_response

            with pytest.raises(KeyEnvError) as exc:
                client.get_project_defaults("nonexistent")

            assert exc.value.status == 404


class TestSetProjectDefaults:
    """Tests for set_project_defaults method."""

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

    def test_set_project_defaults_success(self, client, mock_response):
        mock_defaults = {
            "defaults": [
                {
                    "id": "def_1",
                    "project_id": "proj_1",
                    "environment_name": "development",
                    "default_role": "write",
                    "created_at": "2024-01-01T00:00:00Z",
                },
                {
                    "id": "def_2",
                    "project_id": "proj_1",
                    "environment_name": "production",
                    "default_role": "none",
                    "created_at": "2024-01-01T00:00:00Z",
                },
            ]
        }

        defaults_to_set = [
            {"environment_name": "development", "default_role": "write"},
            {"environment_name": "production", "default_role": "none"},
        ]

        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, mock_defaults)
            result = client.set_project_defaults("proj_1", defaults_to_set)

            mock_request.assert_called_once_with(
                "PUT",
                "/api/v1/projects/proj_1/permissions/defaults",
                json={"defaults": defaults_to_set},
            )
            assert len(result) == 2
            assert isinstance(result[0], ProjectDefault)
            assert result[0].environment_name == "development"
            assert result[0].default_role == "write"

    def test_set_project_defaults_empty_list(self, client, mock_response):
        with patch.object(client._client, "request") as mock_request:
            mock_request.return_value = mock_response(200, {"defaults": []})
            result = client.set_project_defaults("proj_1", [])

            mock_request.assert_called_once_with(
                "PUT",
                "/api/v1/projects/proj_1/permissions/defaults",
                json={"defaults": []},
            )
            assert result == []

    def test_set_project_defaults_forbidden(self, client, mock_response):
        with patch.object(client._client, "request") as mock_request:
            error_response = mock_response(403)
            error_response.json.return_value = {"error": "Only team admins can set project defaults"}
            mock_request.return_value = error_response

            with pytest.raises(KeyEnvError) as exc:
                client.set_project_defaults("proj_1", [{"environment_name": "production", "default_role": "write"}])

            assert exc.value.status == 403


class TestEnvironmentPermissionFromDict:
    """Tests for EnvironmentPermission.from_dict()."""

    def test_from_dict_with_all_fields(self):
        data = {
            "id": "perm_123",
            "environment_id": "env_456",
            "user_id": "user_789",
            "role": "write",
            "user_email": "test@example.com",
            "user_name": "Test User",
            "granted_by": "admin_1",
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-02T00:00:00Z",
        }

        result = EnvironmentPermission.from_dict(data)

        assert result.id == "perm_123"
        assert result.environment_id == "env_456"
        assert result.user_id == "user_789"
        assert result.role == "write"
        assert result.user_email == "test@example.com"
        assert result.user_name == "Test User"
        assert result.granted_by == "admin_1"
        assert result.created_at == "2024-01-01T00:00:00Z"
        assert result.updated_at == "2024-01-02T00:00:00Z"

    def test_from_dict_with_required_fields_only(self):
        data = {
            "id": "perm_123",
            "environment_id": "env_456",
            "user_id": "user_789",
            "role": "read",
        }

        result = EnvironmentPermission.from_dict(data)

        assert result.id == "perm_123"
        assert result.environment_id == "env_456"
        assert result.user_id == "user_789"
        assert result.role == "read"
        assert result.user_email is None
        assert result.user_name is None
        assert result.granted_by is None
        assert result.created_at == ""
        assert result.updated_at == ""

    def test_from_dict_with_all_role_types(self):
        for role in ["none", "read", "write", "admin"]:
            data = {
                "id": "perm_123",
                "environment_id": "env_456",
                "user_id": "user_789",
                "role": role,
            }
            result = EnvironmentPermission.from_dict(data)
            assert result.role == role


class TestMyPermissionFromDict:
    """Tests for MyPermission.from_dict()."""

    def test_from_dict_full(self):
        data = {
            "environment_id": "env_123",
            "environment_name": "production",
            "role": "admin",
            "can_read": True,
            "can_write": True,
            "can_admin": True,
        }

        result = MyPermission.from_dict(data)

        assert result.environment_id == "env_123"
        assert result.environment_name == "production"
        assert result.role == "admin"
        assert result.can_read is True
        assert result.can_write is True
        assert result.can_admin is True

    def test_from_dict_read_only(self):
        data = {
            "environment_id": "env_456",
            "environment_name": "development",
            "role": "read",
            "can_read": True,
            "can_write": False,
            "can_admin": False,
        }

        result = MyPermission.from_dict(data)

        assert result.role == "read"
        assert result.can_read is True
        assert result.can_write is False
        assert result.can_admin is False

    def test_from_dict_write_permission(self):
        data = {
            "environment_id": "env_789",
            "environment_name": "staging",
            "role": "write",
            "can_read": True,
            "can_write": True,
            "can_admin": False,
        }

        result = MyPermission.from_dict(data)

        assert result.role == "write"
        assert result.can_read is True
        assert result.can_write is True
        assert result.can_admin is False

    def test_from_dict_no_permission(self):
        data = {
            "environment_id": "env_999",
            "environment_name": "restricted",
            "role": "none",
            "can_read": False,
            "can_write": False,
            "can_admin": False,
        }

        result = MyPermission.from_dict(data)

        assert result.role == "none"
        assert result.can_read is False
        assert result.can_write is False
        assert result.can_admin is False


class TestProjectDefaultFromDict:
    """Tests for ProjectDefault.from_dict()."""

    def test_from_dict_with_all_fields(self):
        data = {
            "id": "def_123",
            "project_id": "proj_456",
            "environment_name": "production",
            "default_role": "read",
            "created_at": "2024-01-01T00:00:00Z",
        }

        result = ProjectDefault.from_dict(data)

        assert result.id == "def_123"
        assert result.project_id == "proj_456"
        assert result.environment_name == "production"
        assert result.default_role == "read"
        assert result.created_at == "2024-01-01T00:00:00Z"

    def test_from_dict_without_created_at(self):
        data = {
            "id": "def_123",
            "project_id": "proj_456",
            "environment_name": "development",
            "default_role": "write",
        }

        result = ProjectDefault.from_dict(data)

        assert result.id == "def_123"
        assert result.project_id == "proj_456"
        assert result.environment_name == "development"
        assert result.default_role == "write"
        assert result.created_at == ""

    def test_from_dict_with_all_role_types(self):
        for role in ["none", "read", "write", "admin"]:
            data = {
                "id": "def_123",
                "project_id": "proj_456",
                "environment_name": "test",
                "default_role": role,
            }
            result = ProjectDefault.from_dict(data)
            assert result.default_role == role


class TestPermissionsNetworkErrors:
    """Tests for network error handling in permission methods."""

    @pytest.fixture
    def client(self):
        client = KeyEnv(token="test-token")
        yield client
        client.close()

    def test_list_permissions_timeout(self, client):
        with patch.object(client._client, "request") as mock_request:
            mock_request.side_effect = httpx.TimeoutException("Timeout")

            with pytest.raises(KeyEnvError) as exc:
                client.list_permissions("proj_1", "development")

            assert exc.value.status == 408

    def test_set_permission_network_error(self, client):
        with patch.object(client._client, "request") as mock_request:
            mock_request.side_effect = httpx.RequestError("Connection refused")

            with pytest.raises(KeyEnvError) as exc:
                client.set_permission("proj_1", "development", "user_1", "write")

            assert exc.value.status == 0
            assert "Connection refused" in exc.value.message

    def test_bulk_set_permissions_timeout(self, client):
        with patch.object(client._client, "request") as mock_request:
            mock_request.side_effect = httpx.TimeoutException("Request timed out")

            with pytest.raises(KeyEnvError) as exc:
                client.bulk_set_permissions("proj_1", "development", [{"user_id": "u1", "role": "read"}])

            assert exc.value.status == 408

    def test_get_my_permissions_network_error(self, client):
        with patch.object(client._client, "request") as mock_request:
            mock_request.side_effect = httpx.RequestError("DNS resolution failed")

            with pytest.raises(KeyEnvError) as exc:
                client.get_my_permissions("proj_1")

            assert exc.value.status == 0

    def test_delete_permission_timeout(self, client):
        with patch.object(client._client, "request") as mock_request:
            mock_request.side_effect = httpx.TimeoutException("Timeout")

            with pytest.raises(KeyEnvError) as exc:
                client.delete_permission("proj_1", "development", "user_1")

            assert exc.value.status == 408
