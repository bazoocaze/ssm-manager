# ssm-manager

[![Tests](https://github.com/bazoocaze/ssm-manager/actions/workflows/tests.yml/badge.svg)](https://github.com/bazoocaze/ssm-manager/actions/workflows/tests.yml)

A CLI tool that makes **AWS SSM Session Manager** feel like SSH.

Define reusable host profiles in `~/.ssm_config` and connect with a single command:

```
ssm-manager shell development
```

instead of long `aws ssm start-session --target ... --profile ... --region ...` invocations.

## Why?

**Without ssm-manager:**

```bash
aws ssm start-session \
    --target i-0123456789abcdef0 \
    --profile development \
    --region us-east-1
```

**With ssm-manager:**

```bash
ssm-manager shell development
```

Also works for port forwarding:

```bash
ssm-manager pfgw development
```

## Quick Start

```bash
# Install
uv tool install git+https://github.com/bazoocaze/ssm-manager

# Define a host alias
cat >> ~/.ssm_config <<EOF
Host development
    Hostname i-0123456789abcdef0
    Profile my-aws-profile
    Region us-east-1
EOF

# Connect
ssm-manager shell development
```

## Typical Workflow

**1. Define a host** in `~/.ssm_config`:

```
Host development
    Hostname i-0123456789abcdef0
    Profile dev
    Region us-east-1
    LocalForward 8080 10.0.1.24:80
```

> **Remote address is not loopback.** The `session-manager-plugin` refuses to forward to a
> loopback address on the instance — `LocalForward 8080 127.0.0.1:80` fails with
> `Forwarding to IP address 127.0.0.1 is forbidden`. Use the address the instance itself
> can reach: its own private IP (e.g. `10.0.1.24`), or the IP/hostname of another host
> reachable from it (a DB in the same VPC, for example).

**2. Connect to shell:**

```bash
ssm-manager shell development
```

**3. Start a tunnel:**

```bash
ssm-manager pfgw development
```

## Features

- **Shell access** via SSM — no SSH required.
- **Port forwarding** — forward local ports to remote targets.
- **Port forwarding gateway** — on-demand SSM connections (lazy tunnels).
- **Host aliases** — SSH-like `~/.ssm_config` config file.
- **Wildcard patterns** — `Host web-*` matches multiple instances.
- **AWS profile & region** — per-host profile/region settings.
- **Multiple regions** — hosts in different regions, one config file.

## Installation

### With uv (recommended)

```bash
uv tool install git+https://github.com/bazoocaze/ssm-manager
```

### With pip

```bash
pip install git+https://github.com/bazoocaze/ssm-manager
```

### From source

```bash
git clone https://github.com/bazoocaze/ssm-manager
cd ssm-manager
uv tool install -e .
# or: python ssm_manager.py shell <target>
```

Requirements:

- Python 3.12+
- AWS CLI v2 configured with profiles
- IAM permissions for ssm:StartSession

## Commands

| Command                      | Description                                  |
|------------------------------|----------------------------------------------|
| `ssm-manager shell <target>` | Start an SSM shell session                   |
| `ssm-manager pfgw <target>`  | Start port forwarding gateway (lazy tunnels) |
| `ssm-manager -d ...`         | Enable debug output                          |

## Configuration File (`~/.ssm_config`)

INI-like format supporting host aliases, wildcards, and per-host settings.

```
Host i-0123456789abcdef0
    Profile my-aws-profile
    Region us-east-1
    LocalForward 8080 10.0.1.24:80

Host web-*
    Hostname i-0123456789abcdef0
    User ubuntu
    Region us-west-2
    LocalForward 9090 10.0.2.15:443
```

| Directive       | Description                                        |
|-----------------|----------------------------------------------------|
| `Host`          | Target instance-id or pattern                      |
| `Hostname`      | Instance-id to connect to (when Host is a pattern) |
| `User`          | Username for shell session                         |
| `Profile`       | AWS CLI profile                                    |
| `Region`        | AWS region                                         |
| `LocalForward`  | Local port forwarding: `LocalForward <local_port> <remote_addr>:<remote_port>` (remote address must not be loopback) |
