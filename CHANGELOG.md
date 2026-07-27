# Changelog

## 1.0.7 (2026-07-26)

- Shell: SIGINT ignored (passes through to AWS CLI for remote Ctrl+C)
- Shell: SIGTERM/SIGHUP use default handlers (terminate process + child)
- Removed warning log from signal handler to avoid noise on Ctrl+C

## 1.0.6 (2026-07-26)

- Kill entire process group (AWS CLI + session-manager-plugin) on shutdown
- Added timeout fallback: SIGTERM → wait 5s → SIGKILL
- Gateway threads now daemon for faster Ctrl+C exit
- Removed large docstring comment block from script header

## 1.0.5 (2026-07-24)

- Added `-c` / `--config` flag to specify a custom configuration file path
- Updated AGENTS.md with descriptive commit message convention for releases

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
