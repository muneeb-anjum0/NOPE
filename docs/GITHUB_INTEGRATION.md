# NOPE GitHub Integration

Human note: this doc is meant to explain the thing plainly. If something is still limited or local-only, I would rather say that out loud than hide it behind shiny wording.


NOPE supports a secure local GitHub integration contract and real private repository activation when the operator supplies credentials.

## Current Model

The implementation is compatible with a GitHub App/OAuth-style flow and stores connection state in Postgres:

- `github_connections`
- `github_installations`
- `github_repository_references`

Credential material is encrypted before persistence. OAuth/App callback state is one-time and owner-scoped. Repository access is never faked: when credentials are missing, incomplete, expired, revoked, or unverified, the UI and API return a blocked state.

## Local Completion

Locally verified behavior includes:

- connection state and CSRF/state validation
- callback validation
- encrypted credential storage
- repository listing through a controlled HTTP client
- branch selection and default-branch detection
- commit SHA capture
- least-privilege archive retrieval
- snapshot creation through hardened ZIP ingestion
- file-count, size, submodule, and LFS policy checks
- revocation and disconnect state
- ownership isolation and audit logging
- secret-safe logs, remotes, reports, and errors
- protocol tests using a dependency-injected fake GitHub server

## External Activation

Real github.com private repository access requires:

1. Configure the GitHub App/OAuth/token credentials in the NOPE settings/API environment.
2. Install or authorize the integration for the target repository.
3. Verify repository listing succeeds.
4. Run a repository scan and confirm the captured branch and commit SHA.

Until those credentials are supplied and verified, GitHub status is intentionally blocked.

## Not Implemented

NOPE does not currently create pull requests or push branches as part of the product workflow. That patch/PR path was not activated in the local scope.
