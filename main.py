import argparse
import fnmatch
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import traceback

# Global configuration dictionary
CONFIG = {
    "version": "1.0.0",
    "aws_cli": "/home/jose/dados/bin/awss",
    'aws_cli_command': 'aws ssm start-session --target {instance_id} --document-name AWS-StartPortForwardingSession --parameters "portNumber={local_port},localAddress={local_address}"',
    'shell_command': 'aws ssm start-session --target {instance_id}',
    'local_port': 2222,
    'local_address': '127.0.0.1',
    'instance_id': 'i-0123456789abcdef0',  # Replace with your instance ID
    "default_config_file": os.path.expanduser('~/.ssm_manager'),
}


class ApplicationTerminationException(Exception):
    pass


class LocalForwardConfig:
    def __init__(self):
        self.local_port = None
        self.remote_address = None
        self.remote_port = None

    def parse_line(self, line_number, command, extras) -> bool:
        options = extras.split(":")
        try:
            if len(options) == 3:
                self.local_port = int(options[0].strip())
                self.remote_address = options[1].strip()
                self.remote_port = int(options[2].strip())
                return True
        except Exception as ex:
            print(f"WARN:line[{line_number}]: error in local forward configuration: {ex}")
        print(f"WARN:line[{line_number}]: invalid local forward configuration")
        return False

    def __str__(self):
        return (f"LocalForwardConfig(local_port={self.local_port}, remote_address={self.remote_address}, "
                f"remote_port={self.remote_port})")

    __repr__ = __str__


class HostConfig:
    def __init__(self, target, options=None, local_forward=None):
        self._target = target
        self.options = options or {
            "hostname": None,
            "user": None,
            "profile": None,
            "region": None,
        }
        self.local_forward = local_forward or []

    @property
    def target(self):
        return self._target

    @property
    def hostname(self):
        return self.options.get("hostname")

    @property
    def user(self):
        return self.options.get("user")

    @property
    def profile(self):
        return self.options.get("profile")

    @property
    def region(self):
        return self.options.get("region")

    def resolve_hostname(self, source_hostname: str):
        return self.hostname or source_hostname

    def parse_line(self, line_number, command, extras):
        print(f"PARSE_LINE[{line_number}]: {command} {extras}")
        command = command.lower()
        if command == "localforward":
            entry = LocalForwardConfig()
            if entry.parse_line(line_number, command, extras):
                self.local_forward.append(entry)
        elif command in self.options:
            self.options[command] = extras
        else:
            print(f"WARN:line[{line_number}]: unrecognized option {command}")

    @classmethod
    def default_config(cls):
        return HostConfig("default")

    def __str__(self):
        return (f"HostConfig(target={self.target}, hostname={self.hostname}, user={self.user}, "
                f"profile={self.profile}, region={self.region}, local_forward={len(self.local_forward)})")

    __repr__ = __str__


class Config:
    def __init__(self):
        self.config = {"hosts": []}

    def find_host_config(self, target, allow_default=True):
        for host_config in self.config["hosts"]:
            if fnmatch.fnmatch(target, host_config.target):
                return host_config
        if not allow_default:
            print(f"WARN:host not found: {target}")
            return None
        return HostConfig.default_config()

    def _add_host_config(self, host_config):
        self.config["hosts"].append(host_config)

    def read_config_file(self, file_name=None):
        config_path = file_name or CONFIG['default_config_file']
        host_config = None
        line_number = 0
        with open(config_path, 'r') as f:
            for line in f.readlines():
                line_number += 1
                line = line.rstrip().replace('\t', ' ')
                if "#" in line:
                    line = line[:line.index("#")].rstrip()
                print(f"READ[{line_number}]: {line}")
                if not line:
                    continue
                if not line.startswith(" "):
                    target = line.split(" ", maxsplit=1)[1].strip()
                    host_config = HostConfig(target)
                    self._add_host_config(host_config)
                elif host_config:
                    command = line.strip().split(" ", maxsplit=1)
                    host_config.parse_line(line_number, command[0], command[1])


class LocalForwardSimpleController:
    def __init__(self, instance_id: str, host_config: HostConfig, local_forward_config: LocalForwardConfig):
        self._instance_id = instance_id
        self._host_config = host_config
        self._local_forward_config = local_forward_config
        self._external_process: subprocess.Popen = None
        self._external_process_exit_code = None

    def start(self):
        if self.is_running():
            return
        self._run()

    def stop(self):
        if self.is_running():
            print("DEBUG:controller:stop: finishing")
            self._external_process.terminate()
            self._external_process.wait()
            print("DEBUG:controller:stop: external process finished")
        else:
            print("DEBUG:controller:stop: not running")

    def is_running(self):
        if self._external_process is None or self._external_process_exit_code is not None:
            return False

        self._external_process_exit_code = self._external_process.poll()
        return self._external_process_exit_code is None

    def _run(self):
        local_port = self._local_forward_config.local_port
        command_line = [CONFIG["aws_cli"]]
        if self._host_config.profile:
            command_line += ["--profile", self._host_config.profile]
        if self._host_config.region:
            command_line += ["--region", self._host_config.region]
        command_line += ["ssm", "start-session", "--target", self._instance_id,
                         "--document-name", "AWS-StartPortForwardingSession",
                         "--parameters", f"portNumber={local_port},localAddress=local_address"]

        print(f"EXEC: {command_line}")
        self._external_process_exit_code = None
        self._external_process = subprocess.Popen(command_line, shell=False)
        print("DEBUG:external process started")


# Function to read configuration from ~/.ssm_manager file
def read_config_file():
    config_path = os.path.expanduser('~/.ssm_manager')
    config = Config()
    config.read_config_file(config_path)
    return config


# Function to handle client connections for port forwarding
def handle_client(client_socket, local_port):
    try:
        # Start the AWS CLI SSM port forward command
        aws_command = CONFIG['aws_cli_command'].format(
            instance_id=CONFIG['instance_id'],
            local_port=local_port,
            local_address=CONFIG['local_address']
        )
        process = subprocess.Popen(aws_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Wait for the port forward to start
        time.sleep(2)  # Adjust this delay if necessary

        # Connect the client socket to the local port
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((CONFIG['local_address'], local_port))

        # Forward data between client and server
        def forward_data(source, destination):
            try:
                while True:
                    data = source.recv(4096)
                    if not data:
                        break
                    destination.sendall(data)
            except Exception as e:
                print(f"Error forwarding data: {e}")

        threading.Thread(target=forward_data, args=(client_socket, server_socket)).start()
        threading.Thread(target=forward_data, args=(server_socket, client_socket)).start()

    finally:
        client_socket.close()
        server_socket.close()
        process.terminate()


# Function to start the gateway for port forwarding
def start_gateway():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', CONFIG['local_port']))
    server.listen(5)
    print(f"Gateway listening on port {CONFIG['local_port']}")

    while True:
        client_socket, addr = server.accept()
        print(f"Accepted connection from {addr}")
        threading.Thread(target=handle_client, args=(client_socket, CONFIG['local_port'])).start()


def command_port_forwarding(args):
    target = args.target
    config = read_config_file()
    host_config = config.find_host_config(target, allow_default=False)
    if not host_config:
        return
    if not host_config.local_forward:
        print("WARN: no local forward configuration found")
        return

    instance_id = host_config.resolve_hostname(target)
    controllers = []

    try:
        print("DEBUG:PF: starting")
        for local_forward in host_config.local_forward:
            controller = LocalForwardSimpleController(instance_id, host_config, local_forward)
            controllers.append(controller)
            controller.start()
        while controllers:
            time.sleep(3)
            for controller in controllers.copy():
                if not controller.is_running():
                    controllers.remove(controller)

    finally:
        print("DEBUG:PF: finishing")
        for controller in controllers:
            controller.stop()
        print("DEBUG:PF: finished")


# Function to start a shell session using SSM
def command_start_shell(target):
    config = read_config_file()
    host_config = config.find_host_config(target)

    instance_id = host_config.resolve_hostname(target)
    profile = host_config.profile
    region = host_config.region

    command_line = [CONFIG["aws_cli"]]
    if profile:
        command_line += ["--profile", profile]
    if region:
        command_line += ["--region", region]
    command_line += ["ssm", "start-session", "--target", instance_id]

    print(f"EXEC: {command_line}")
    try:
        subprocess.run(command_line, shell=False)
    finally:
        print("DEBUG:remote shell session finished")


def _parse_args():
    parser = argparse.ArgumentParser(description='SSM Port Forwarding and Shell Access', prog='ssm-manager')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + CONFIG['version'])
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Subparser for port forwarding
    pf_parser = subparsers.add_parser('pf', help='Start port forwarding')
    pf_parser.add_argument('target', help='Target instance ID or pattern from config file')

    # Subparser for shell access
    shell_parser = subparsers.add_parser('shell', help='Connect to remote host using SSM (no SSH)')
    shell_parser.add_argument('target', help='Target instance ID or pattern from config file')

    return parser.parse_args(), parser


def _signal_handler(signum, frame):
    raise ApplicationTerminationException("Received SIGTERM")


def main():
    signal.signal(signal.SIGTERM, _signal_handler)
    args, parser = _parse_args()
    try:
        if args.command == 'shell':
            return command_start_shell(args.target)
        elif args.command == 'pf':
            return command_port_forwarding(args)
        else:
            parser.print_help()
            return 1
    except (KeyboardInterrupt, ApplicationTerminationException):
        print("Interrupted")
        return 127
    except Exception as e:
        print(f"ERROR: {e}")
        traceback.print_exc()
        return 126


if __name__ == '__main__':
    ret = main()
    sys.exit(ret)
