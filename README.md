# KeyEnv Python SDK

Official Python SDK for [KeyEnv](https://keyenv.dev) - Secure secrets management for development teams.

## Installation

```bash
pip install keyenv
```

## Quick Start

```python
from keyenv import KeyEnv
import os

client = KeyEnv(token=os.environ["KEYENV_TOKEN"])

# Load secrets into os.environ
client.load_env("your-project-id", "production")
print(os.environ["DATABASE_URL"])
```

## Usage

### Initialize the Client

```python
from keyenv import KeyEnv

client = KeyEnv(token="your-service-token")

# Use as context manager for automatic cleanup
with KeyEnv(token="your-token") as client:
    secrets = client.export_secrets("project-id", "production")
```

### Export Secrets

```python
# Get all secrets as a list
secrets = client.export_secrets("project-id", "production")
for secret in secrets:
    print(f"{secret.key}={secret.value}")

# Get secrets as a dictionary
env = client.export_secrets_as_dict("project-id", "production")
print(env["DATABASE_URL"])

# Load directly into os.environ
count = client.load_env("project-id", "production")
print(f"Loaded {count} secrets")
```

### Manage Secrets

```python
# Get a single secret
secret = client.get_secret("project-id", "production", "DATABASE_URL")
print(secret.value)

# Set a secret (creates or updates)
client.set_secret("project-id", "production", "API_KEY", "sk_live_...")

# Delete a secret
client.delete_secret("project-id", "production", "OLD_KEY")
```

### Bulk Import

```python
from keyenv import BulkSecretItem

result = client.bulk_import(
    "project-id",
    "development",
    [
        BulkSecretItem(key="DATABASE_URL", value="postgres://localhost/mydb"),
        BulkSecretItem(key="REDIS_URL", value="redis://localhost:6379"),
        {"key": "API_KEY", "value": "sk_test_..."},  # Also accepts dicts
    ],
    overwrite=True,
)
print(f"Created: {result.created}, Updated: {result.updated}")
```

### Generate .env File

```python
env_content = client.generate_env_file("project-id", "production")
with open(".env", "w") as f:
    f.write(env_content)
```

### List Projects and Environments

```python
# List all projects
projects = client.list_projects()
for project in projects:
    print(f"{project.name} ({project.id})")

# Get project with environments
project = client.get_project("project-id")
for env in project.environments:
    print(f"  - {env.name}")
```

### Service Token Info

```python
# Get current user or service token info
user = client.get_current_user()

if user.auth_type == "service_token":
    # Service tokens can access multiple projects
    print(f"Projects: {user.project_ids}")
    print(f"Scopes: {user.scopes}")
```

## Error Handling

```python
from keyenv import KeyEnv, KeyEnvError

try:
    secret = client.get_secret("project-id", "production", "MISSING_KEY")
except KeyEnvError as e:
    print(f"Error {e.status}: {e.message}")
    if e.status == 404:
        print("Secret not found")
```

## Type Hints

The SDK includes full type annotations for better IDE support:

```python
from keyenv import Secret, SecretWithValue, Project
```

## API Reference

### `KeyEnv(token, timeout)`

Create a new KeyEnv client.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `token` | `str` | Yes | - | Service token |
| `timeout` | `float` | No | `30.0` | Request timeout (seconds) |

### Methods

| Method | Description |
|--------|-------------|
| `get_current_user()` | Get current user/token info |
| `list_projects()` | List all accessible projects |
| `get_project(id)` | Get project with environments |
| `list_environments(project_id)` | List environments in a project |
| `list_secrets(project_id, env)` | List secret keys (no values) |
| `export_secrets(project_id, env)` | Export secrets with values |
| `export_secrets_as_dict(project_id, env)` | Export as dictionary |
| `get_secret(project_id, env, key)` | Get single secret |
| `set_secret(project_id, env, key, value)` | Create or update secret |
| `delete_secret(project_id, env, key)` | Delete secret |
| `bulk_import(project_id, env, secrets)` | Bulk import secrets |
| `load_env(project_id, env)` | Load secrets into os.environ |
| `generate_env_file(project_id, env)` | Generate .env file content |

## License

MIT
