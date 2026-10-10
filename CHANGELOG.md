# Changelog

## 1.0.9 (2026-10-10)

- Gateway (`pfgw`): replaced the exponential retry backoff (0.25s doubling to 16s, 8 attempts, ~32s cap) with a fixed 0.5s poll and a 60s budget, so the first connection no longer waits up to 16s for the SSM port to bind — fixes first-connection failures when the client timeout is shorter than the backoff window
- Gateway: fail fast when the `aws ssm start-session` subprocess dies before binding the port (previously it burned the whole backoff)
- Gateway: close the inner tunnel socket when the connect attempt fails
- Added `import time` (was missing; the module relied only on `Event.wait`)
- Added `tests/test_gateway.py` covering the retry poll, fail-fast, timeout budget and late-binding listener

## 1.0.8 (2026-07-26)

- Fixed shell command injection via `user` config: uses `shlex.quote()` + `json.dumps()`
- Added `json` and `shlex` stdlib imports

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
