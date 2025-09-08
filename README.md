# Portainer Config

A command-line tool to manage Portainer configuration declaratively, using a YAML file. This allows you to treat your Portainer setup as code (Infrastructure as Code).

The tool connects to a Portainer instance, reads a local configuration file, and synchronizes the state of various resources like users, teams, endpoints, and authentication settings.

## Features

*   **Teams**: Ensures specified teams exist.
*   **Users**: Creates users if they don't exist and synchronizes their team memberships and roles.
*   **Endpoint Groups**: Creates and updates endpoint groups, including their descriptions and team access policies.
*   **Endpoints**: Creates and updates endpoints (Kubernetes, Docker), assigning them to the correct group.
*   **OIDC Authentication**: Configures OIDC as an authentication method.

## Usage

The recommended way to run this tool is via its Docker image, which is published to the GitHub Container Registry.

### Docker

You need a `config.yaml` file to define your desired Portainer configuration.

```bash
docker run --rm -it \
  -v $(pwd)/config.yaml:/app/config.yaml \
  -e PORTAINER_PASSWORD="your-portainer-admin-password" \
  -e OIDC_CLIENT_SECRET="your-oidc-client-secret" \
  ghcr.io/codestation/portainer-config:latest
```

### Environment Variables

The tool uses environment variables for sensitive data and optional configuration overrides.

*   `CONFIG_PATH`: Path to the configuration file inside the container. Defaults to `config.yaml`.
*   `PORTAINER_PASSWORD`: The password for the Portainer admin user. This overrides the `password` field in `config.yaml`.
*   `OIDC_CLIENT_SECRET`: The client secret for your OIDC provider. This overrides the `clientSecret` field in the OIDC configuration.

## Configuration

The tool is configured using a single YAML file (e.g., `config.yaml`).

### Example `config.yaml`

```yaml
url: "portainer.example.com"
auth:
  username: "admin"
  # It's recommended to use the PORTAINER_PASSWORD environment variable instead of setting the password here.
  password: "your-password"

teams:
  - "developers"
  - "operations"

users:
  - name: "dev-lead"
    admin: false
    teams:
      - name: "developers"
        role: "leader" # "leader" or "member"
  - name: "ops-user"
    admin: false
    teams:
      - name: "operations"
        role: "member"
      - name: "developers"
        role: "member"

endpointGroups:
  - name: "Production"
    description: "Production Kubernetes Clusters"
    accessPolicies:
      - team: "operations"
        role: "standard-user"
  - name: "Development"
    description: "Development Docker Environments"
    accessPolicies:
      - team: "developers"
        role: "standard-user"

endpoints:
  - name: "k8s-prod-cluster"
    type: "kubernetes" # "kubernetes" or "docker"
    url: "https://1.2.3.4:6443"
    group: "Production"
  - name: "docker-dev-host"
    type: "docker"
    url: "tcp://portainer-agent-host:9001"
    group: "Development"

oidc:
  enabled: true
  issuerURL: "https://keycloak.example.com/realms/myrealm"
  clientID: "portainer"
  # It's recommended to use the OIDC_CLIENT_SECRET environment variable.
  clientSecret: "your-oidc-secret"
  scopes:
    - "openid"
    - "profile"
    - "email"
  userIdentifier: "preferred_username"
  accessTokenURI: "https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token"
  authorizationURI: "https://keycloak.example.com/realms/myrealm/protocol/openid-connect/auth"
  resourceURI: "https://keycloak.example.com/realms/myrealm/protocol/openid-connect/userinfo"
  logoutURI: "https://keycloak.example.com/realms/myrealm/protocol/openid-connect/logout"
  redirectURI: "https://portainer.example.com"
  defaultTeam: "developers"
```
