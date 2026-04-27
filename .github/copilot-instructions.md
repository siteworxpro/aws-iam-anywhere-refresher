# Copilot Instructions

## Commands

```bash
# Build
go build -o aws-iam-anywhere-refresher .

# Test (all packages)
go test ./...

# Test (single package)
go test ./aws_signing_helper/...

# Docker build
docker build -t siteworxpro/aws-iam-anywhere .
```

Private module resolution requires `GOPRIVATE=git.siteworxpro.com`.

## Architecture

One-shot binary designed as a Kubernetes CronJob. Runs once, refreshes AWS IAM Anywhere credentials, writes them to a Kubernetes Secret, and exits. No server mode, no persistent state.

**Execution flow:**
1. `config/config.go` — reads all configuration from env vars; `PRIVATE_KEY` and `CERTIFICATE` are base64-encoded PEM strings decoded at read time
2. `cmd/credential_process.go` — thin wrapper calling `GetSigner` then `GenerateCredentials`
3. `aws_signing_helper/` — vendored+modified fork of [aws/rolesanywhere-credential-helper](https://github.com/aws/rolesanywhere-credential-helper); handles SigV4-X509 signing and the `CreateSession` API call; supports file, PKCS#11, and TPM signers
4. `kube_client/client.go` — in-cluster Kubernetes client; creates or updates the target Secret, and optionally restarts Deployments labeled `iam-role-type=aws-iam-anywhere`

**`FETCH_ONLY=true`** skips all Kubernetes operations and prints credentials to stderr — use this for local testing without a cluster.

## Key Conventions

- **Config is stateless**: `Config` is an empty struct — all values are read from env vars on each method call via the `gitea.siteworxpro.com/golang-packages/utilities/Env` package.
- **Logging**: All output goes to `stderr` via `charmbracelet/log` at `DebugLevel`. No stdout output except credentials in `FETCH_ONLY` mode.
- **Deployment restart mechanism**: Restarts are triggered by patching `kubectl.kubernetes.io/restartedAt` on the pod template annotation — only affects Deployments with label `iam-role-type=aws-iam-anywhere`.
- **`aws_signing_helper/` is a vendored fork** — avoid making structural changes here; it tracks upstream `aws/rolesanywhere-credential-helper`.
- **Exit codes**: `0` success, `1` config/k8s error, `3` credential fetch failure.

## Repo & CI

- **Gitea repo**: `gitea.siteworxpro.com/Siteworxpro/aws-iam-anywhere-refresher` — use Gitea MCP tools, not `gh`
- **CI**: Triggers on `v*` tags; pushes to Docker Hub as `siteworxpro/aws-iam-anywhere:<tag>` and `:latest`
- **Base images**: `siteworxpro/golang:1.26.2` (build), `siteworxpro/alpine:3.23.4` (runtime)
- **Required CI secrets**: `DOCKER_USERNAME`, `DOCKER_PASSWORD`
