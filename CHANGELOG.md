# Changelog

## 1.0.0 (2026-07-23)

- Stable release
- `ssm shell <target>` — start an interactive SSM shell session
- `ssm pf <target>` — simple TCP port forwarding via SSM
- `ssm pfgw <target>` — on-demand (gateway) port forwarding with lazy tunnels
- Configuration file (`~/.ssm_manager`) with support for `Host`, `User`, `Port`, `LocalForward`, `Profile`, `Region`
- Wildcard matching on host patterns
- Debug mode (`-d` / `--debug`)
