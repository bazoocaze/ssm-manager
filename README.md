# ssm-manager

`ssm-manager` is a command-line tool that simplifies working with **AWS SSM Session Manager** for shell access and port
forwarding.
It allows you to configure reusable host profiles (similar to `ssh_config`) and then connect with a single command.

## Features

- **Shell access** via AWS SSM (no need for SSH).
- **Simple port forwarding**: forward local ports to remote targets.
- **Port forwarding gateway**: starts SSM connections on demand, useful for lazy tunnels.
- **Config file support** (`~/.ssm_manager`) for reusable host definitions.
- **Wildcard matching** for host targets.
- Debug mode for troubleshooting.

## Installation

Clone this repository and make the script executable:

```bash
git clone https://github.com/bazoocaze/ssm-manager
cd ssm-manager
pipenv install
chmod +x ssm_manager.sh
```

(Optional) Create a symlink to use ssm-manager as a command:

```bash
ln -s $(pwd)/ssm_manager.py /usr/local/bin/ssm-manager
```

Requirements:

- Python 3.12+
- AWS CLI v2 configured with profiles
- IAM permissions for ssm:StartSession

## Usage

### General Help

```bash
ssm-manager --help
```

### Connect to a Shell

```bash
ssm-manager shell <target>
```

### Start Port Forwarding

```bash
ssm-manager pf <target>
```

### Start Port Forwarding Gateway

```bash
ssm-manager pfgw <target>
```

Add `-d` for debug output:

```bash
ssm-manager -d shell my-instance
```

## Configuration File (`~/.ssm_manager`)

The configuration file works similarly to `ssh_config`. Example:

```
# Define a host using instance-id

Host i-0123456789abcdef0
  Profile my-aws-profile
  Region us-east-1
  LocalForward 8080:127.0.0.1:80

# Use patterns
Host web-*
  Hostname i-0123456789abcdef0
  Region us-west-2
  LocalForward 9090:127.0.0.1:443
```

- `Host <pattern>`: Target instance-id or pattern.
- `Hostname <instance-id>`: instance-id to connect to.
- `Profile`: AWS CLI profile.
- `Region`: AWS region.
- `LocalForward <local_port>:<remote_addr>:<remote_port>`: Configure tunnels.
