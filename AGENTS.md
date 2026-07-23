# ssm-manager — Agent Guide

## Overview

Single-file Python tool for AWS SSM Session Manager. Provides `shell`, `pf`, and `pfgw` subcommands to connect to EC2 instances without SSH.

## Project Structure

```
ssm-manager/
  pyproject.toml        # Build config, entry point: `ssm = ssm_manager:main`
  ssm_manager.py        # All source code (single file, ~650 lines)
  tests/                # pytest test suite
    __init__.py
    conftest.py
    test_config.py
    test_cli.py
    test_utils.py
  README.md             # User documentation
  CHANGELOG.md          # Release history
  AGENTS.md             # This file
  LICENSE               # MIT
  .gitignore
```

## Entry Point

`pyproject.toml` defines:

```toml
[project.scripts]
ssm = "ssm_manager:main"

[tool.setuptools]
py-modules = ["ssm_manager"]
```

After `uv tool install .` or `pip install .`, the `ssm` command calls `ssm_manager.main()`.

## Local Development

No virtual environment required — zero Python dependencies (stdlib only).

```bash
# Run directly
python ssm_manager.py shell my-instance

# Or install in dev mode (entry point `ssm`)
uv tool install -e .
ssm shell my-instance
```

Requires **AWS CLI v2** installed and configured (called as `aws` subprocess).

## Architecture

| Module (inside `ssm_manager.py`) | Responsibility |
|---|---|
| `Config` / `HostConfig` / `LocalForwardConfig` | Parse `~/.ssm_manager` config file |
| `command_start_shell()` | `shell` subcommand — spawns `aws ssm start-session` |
| `command_port_forwarding()` | `pf` subcommand — one SSM session per `LocalForward`, kept alive |
| `command_port_forwarding_gateway()` | `pfgw` subcommand — lazy tunnels via local TCP listener |
| `_parse_args()` | `argparse` CLI definition |
| `main()` | Entry point — parsing, signal handling, dispatch |
| Utility functions | `delay()`, `get_free_port()`, `configure_tcp_socket()`, `execute_silently()` |

### Key technical details

- **No threading in `shell` or `pf`** — simple subprocess with `run()`.
- **Gateway mode (`pfgw`)** uses `threading.Thread` + `socket` for on-demand connections.
- **AWS CLI invocation**: `aws ssm start-session` with `--document-name` and `--parameters` JSON. Port forwarding uses the `AWS-StartPortForwardingSessionToRemoteHost` document.
- **Config file**: `~/.ssm_manager`, INI-like format parsed by `ConfigParser`-style custom parser (not `configparser` stdlib). Supports `Host`, `Hostname`, `User`, `Port`, `LocalForward`, `Profile`, `Region`.

## Coding Conventions

- No external Python dependencies — stdlib only.
- Type hints where practical (`list[T]`, `| None`, etc. — Python 3.9+ compat).
- `argparse` for CLI (no click/typer).
- AWS CLI invoked via `subprocess`, not `boto3`.
- Signal handlers for graceful shutdown (SIGTERM, SIGINT, SIGHUP).
- Logging via `logging` module; debug mode sets level to `DEBUG`.

## Adding a New Subcommand

1. Add a new function `command_<name>()` following the signature of existing commands.
2. Register it in `_parse_args()` with `add_parser()`.
3. Add dispatch in `main()` after the `if args.subcommand == ...` chain.
4. Document in `README.md`, `CHANGELOG.md`, and this file.

## Testing

Tests use `pytest` installed in a local `.venv` (managed by `uv`). Setup:

```bash
uv venv
uv sync --group dev
```

Run tests:

```bash
uv run pytest tests/ -v
```

What to test:
- Config parsing (`Config`, `HostConfig`, `LocalForwardConfig`)
- Argument parsing (`_parse_args`)
- Utility functions (`execute_silently`, `get_free_port`, `configure_tcp_socket`, `delay`)
- Do **not** test AWS CLI integration (requires real credentials).

## Building

```bash
pip install build
python -m build
# Produces dist/ssm_manager-1.0.0.tar.gz and .whl
```

## Make Release

When the user asks to "make release" or "release a new version":

1. Ask which version bump (major.minor.patch) or read the explicit version from the user.
2. Use SemVer convention:
   - **patch** — fixes, minor breaking changes, new small features.
   - **minor** — new medium features, medium breaking changes.
   - **major** — always confirm with the user before incrementing.
3. Update `pyproject.toml` — set `version = "X.Y.Z"`.
4. Update `CHANGELOG.md` — add a new entry `## X.Y.Z (YYYY-MM-DD)` with the changes.
5. Update `README.md` if any feature/usage changes are relevant.
6. Update `AGENTS.md` if project structure or conventions changed.
7. Commit with message `release X.Y.Z`.
8. Push to origin.
