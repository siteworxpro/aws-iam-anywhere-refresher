# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build
go build -o aws-iam-anywhere-refresher .

# Test
go test ./...

# Single package test
go test ./aws_signing_helper/...

# Docker build
docker build -t siteworxpro/aws-iam-anywhere .
```

## Architecture

One-shot Kubernetes CronJob binary. Runs, refreshes credentials, exits. No server mode, no persistent state.

**Flow:**
1. `config/config.go` — reads all config from env vars; `PRIVATE_KEY` and `CERTIFICATE` are base64-encoded PEM, decoded at read time
2. `cmd/credential_process.go` — thin wrapper: calls `GetSigner` then `GenerateCredentials`
3. `aws_signing_helper/` — vendored+modified fork of [aws/rolesanywhere-credential-helper](https://github.com/aws/rolesanywhere-credential-helper); handles SigV4-X509 signing and the `CreateSession` API call; supports file, PKCS#11, and TPM signers
4. `kube_client/client.go` — in-cluster k8s client; creates or updates the target Secret, optionally restarts Deployments labeled `iam-role-type=aws-iam-anywhere`

**`FETCH_ONLY=true`** skips all Kubernetes operations and just prints credentials to stderr — useful for local testing without a cluster.

## Repo & CI

- Gitea repo: `gitea.siteworxpro.com/Siteworxpro/aws-iam-anywhere-refresher` — use gitea MCP tools, not `gh`
- CI triggers on `v*` tags; pushes to Docker Hub as `siteworxpro/aws-iam-anywhere:<tag>` and `:latest`
- Base images: `siteworxpro/golang:1.25.3` (build), `siteworxpro/alpine:3.21.4` (runtime)
- `GOPRIVATE=git.siteworxpro.com` required for private module resolution
