# ssm-manager

[![Tests](https://github.com/bazoocaze/ssm-manager/actions/workflows/tests.yml/badge.svg)](https://github.com/bazoocaze/ssm-manager/actions/workflows/tests.yml)

A CLI tool that makes **AWS SSM Session Manager** feel like SSH.

Define reusable host profiles in `~/.ssm_manager` and connect with a single command:

```
ssm-manager shell production
```

instead of long `aws ssm start-session --target ... --profile ... --region ...` invocations.

## Why?

**Without ssm-manager:**

```bash
aws ssm start-session \
    --target i-0123456789abcdef0 \
    --profile production \
    --region us-east-1
```

**With ssm-manager:**

```bash
ssm-manager shell production
```

Also works for port forwarding:

```bash
ssm-manager pf production
```

## Quick Start

```bash
# Install
uv tool install git+https://github.com/bazoocaze/ssm-manager

# Define a host alias
cat >> ~/.ssm_manager <<EOF
Host production
    Hostname i-0123456789abcdef0
    Profile my-aws-profile
    Region us-east-1
EOF

# Connect
ssm-manager shell production
```

## Typical Workflow

**1. Define a host** in `~/.ssm_manager`:

```
Host production
    Hostname i-0123456789abcdef0
    Profile prod
    Region us-east-1
    LocalForward 8080 127.0.0.1:80
```

**2. Connect to shell:**

```bash
ssm-manager shell production
```

**3. Start a tunnel:**

```bash
ssm-manager pf production
```

## Features

- **Shell access** via SSM — no SSH required.
- **Port forwarding** — forward local ports to remote targets.
- **Port forwarding gateway** — on-demand SSM connections (lazy tunnels).
- **Host aliases** — SSH-like `~/.ssm_manager` config file.
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

| Command                | Description                                  |
|------------------------|----------------------------------------------|
| `ssm-manager shell <target>`  | Start an SSM shell session                   |
| `ssm-manager pf <target>`     | Start port forwarding                        |
| `ssm-manager pfgw <target>`   | Start port forwarding gateway (lazy tunnels) |
| `ssm-manager -d ...`          | Enable debug output                          |

## Configuration File (`~/.ssm_manager`)

INI-like format supporting host aliases, wildcards, and per-host settings.

```
Host i-0123456789abcdef0
    Profile my-aws-profile
    Region us-east-1
    LocalForward 8080:127.0.0.1:80

Host web-*
    Hostname i-0123456789abcdef0
    User ubuntu
    Region us-west-2
    LocalForward 9090 127.0.0.1:443
```

| Directive       | Description                                        |
|-----------------|----------------------------------------------------|
| `Host`          | Target instance-id or pattern                      |
| `Hostname`      | Instance-id to connect to (when Host is a pattern) |
| `User`          | Username for shell session                         |
| `Profile`       | AWS CLI profile                                    |
| `Region`        | AWS region                                         |
| `LocalForward`  | Local port forwarding rule                         |
