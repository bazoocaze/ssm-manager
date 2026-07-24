# Changelog

## 1.0.4 (2026-07-23)

- Version now read dynamically from package metadata via `importlib.metadata` instead of hardcoded value

## 1.0.3 (2026-07-23)

- Added `run-tests.sh` convenience script

## 1.0.2 (2026-07-23)

- Fixed GitHub Actions workflow branch from `main` to `master`

## 1.0.1 (2026-07-23)

- Added test suite (pytest, 35 tests)
- Added GitHub Actions CI workflow
- Added test status badge to README
- Added dev dependency group in pyproject.toml
- Updated AGENTS.md with testing instructions

## 1.0.0 (2026-07-23)

- Stable release
- `ssm shell <target>` — start an interactive SSM shell session
- `ssm pf <target>` — simple TCP port forwarding via SSM
- `ssm pfgw <target>` — on-demand (gateway) port forwarding with lazy tunnels
- Configuration file (`~/.ssm_manager`) with support for `Host`, `User`, `Port`, `LocalForward`, `Profile`, `Region`
- Wildcard matching on host patterns
- Debug mode (`-d` / `--debug`)
