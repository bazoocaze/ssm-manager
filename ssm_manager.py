#!/usr/bin/env python3
"""
SSM Connection Manager

Comandos:
  - shell <[user@]host>
      Conecta uma sessão SSM com o host remoto
  - pf <host>
      Sobe todos os port-forwardings definidos para o host e mantém até Ctrl+C
  - pfgw <host>
      Gateway de port-forwardings, onde a conexão SSM é feita sob demanda (Ctrl+C para finalizar)

Configuração: ~/.ssm_config (semelhante ao ~/.ssh/config)
Exemplo:

  Host app-*
    Hostname i-0123456789abcdef0
    User ubuntu
    Profile prod
    Region us-east-1
    ProxyCommand aws ssm start-session --target {target} --region {region} --profile {profile}
    LocalForward 15432 127.0.0.1:5432
    LocalForward 18080 localhost:8080

Notas:
- Hostname (opcional) define o "target" SSM; se ausente, usa o nome do Host.
- User (opcional) define o usuário para a sessão SSM interativa.
- Profile (opcional) mapeia para --profile do AWS CLI.
- Region (opcional) default em CONFIG['DEFAULT_REGION'].
- ProxyCommand (opcional) usado APENAS no comando "shell"; ignorado em "pf".
- LocalForward N host:port pode ocorrer múltiplas vezes.
- Se o host não for encontrado e parecer um instance-id (i-* ou mi-*), tenta conexão direta.

Requisitos:
- awscli instalado e autenticado.
- Permissões de SSM para start-session e documentos de PF.
"""

import argparse
import fnmatch
import logging
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import traceback
from threading import Thread

# Global configuration
CONFIG = {
    "version": "1.0.0",
    "aws_cli": "aws",
    "default_config_file": os.path.expanduser('~/.ssm_config'),
    "debug": False,
    "exit_signal": False,
}

logger = logging.getLogger(__name__)


class ApplicationTerminationException(Exception):
    pass


class LocalForwardConfig:
    def __init__(self):
        self.local_port = None
        self.remote_address = None
        self.remote_port = None
        self._logger = logging.getLogger(self.__class__.__name__)

    def parse_line(self, line_number, command, extras) -> bool:
        try:
            extras = (extras + " - -").split(" ")
            options = extras[1].split(":")
            if len(options) == 2:
                self.local_port = int(extras[0].strip())
                self.remote_address = options[0].strip()
                self.remote_port = int(options[1].strip())
                return True
            self._logger.warning(f"line[{line_number}]: invalid local forward configuration")
        except Exception as ex:
            self._logger.warning(f"line[{line_number}]: error in local forward configuration: {ex}")
        return False

    def __str__(self):
        return (f"LocalForwardConfig(local_port={self.local_port}, remote_address={self.remote_address}, "
                f"remote_port={self.remote_port})")

    __repr__ = __str__

    def with_random_local_port(self):
        updated = LocalForwardConfig()
        updated.local_port = 0
        updated.remote_address = self.remote_address
        updated.remote_port = self.remote_port
        return updated


class HostConfig:
    def __init__(self, target, options=None, local_forward: list[LocalForwardConfig] = None):
        self._target = target
        self.options = options or {
            "hostname": None,
            "user": None,
            "profile": None,
            "region": None,
        }
        self.local_forward = local_forward or []
        self._logger = logging.getLogger(self.__class__.__name__)

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
        command = command.lower()
        if command == "localforward":
            entry = LocalForwardConfig()
            if entry.parse_line(line_number, command, extras):
                self.local_forward.append(entry)
        elif command in self.options:
            self.options[command] = extras
        else:
            self._logger.warning(f"line[{line_number}]: unrecognized option {command}")

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
        self._logger = logging.getLogger(self.__class__.__name__)

    def find_host_config(self, target, allow_default=True):
        for host_config in self.config["hosts"]:
            if fnmatch.fnmatch(target, host_config.target):
                return host_config
        if not allow_default:
            self._logger.error(f"host not found: {target}")
            return None
        return HostConfig.default_config()

    def _add_host_config(self, host_config):
        self.config["hosts"].append(host_config)

    def read_config_file(self, file_name=None) -> bool:
        config_path = file_name or CONFIG['default_config_file']
        host_config = None
        line_number = 0
        with open(config_path, 'r') as f:
            for line in f.readlines():
                line_number += 1
                if "#" in line:
                    line = line[:line.index("#")].strip()
                line = line.replace('\t', ' ').strip()
                if not line:
                    continue
                line_split = line.split(" ", maxsplit=1)
                command = line_split[0].lower()
                if command == "host":
                    if len(line_split) < 2:
                        self._logger.error(f"line[{line_number}]: invalid host definition line")
                        return False
                    target = line_split[1].strip()
                    host_config = HostConfig(target)
                    self._add_host_config(host_config)
                elif host_config:
                    if len(line_split) < 2:
                        self._logger.warning(f"line[{line_number}]: invalid configuration line")
                        continue
                    host_config.parse_line(line_number, command, line_split[1])
                else:
                    self._logger.error(f"line[{line_number}]: invalid command outset Host definition")
                    return False
        return True


class LocalForwardSimpleController:
    def __init__(self, instance_id: str, host_config: HostConfig, local_forward_config: LocalForwardConfig):
        self._instance_id = instance_id
        self._host_config = host_config
        self._local_forward_config = local_forward_config

        self._external_process: subprocess.Popen = None
        self._external_process_exit_code = None
        self._logger = logging.getLogger(self.__class__.__name__)
        self._effective_port = None
        self._remote_desc = f"{self._local_forward_config.remote_address}:{self._local_forward_config.remote_port}"

    def start(self):
        if self.is_running():
            return
        try:
            self._run()
        except Exception as ex:
            raise Exception(f"Failed to start SSM for port {self._local_forward_config.local_port}: {ex}")

    def stop(self):
        if self.is_running():
            self._logger.debug("stop -> finishing")
            self._external_process.terminate()
            self._external_process.wait()
            self._logger.debug("stop -> external process finished")
        else:
            self._logger.debug("stop -> not running")

    def is_running(self):
        if self._external_process is None or self._external_process_exit_code is not None:
            return False

        self._external_process_exit_code = self._external_process.poll()
        return self._external_process_exit_code is None

    def get_effective_local_port(self):
        return self._effective_port or self._local_forward_config.local_port

    def _get_local_port_to_use(self):
        port = self._local_forward_config.local_port
        if port:
            return port
        free_port = get_free_port()
        self._logger.info(f"Selected port {free_port} to start SSM instance -> {self._remote_desc}")
        return free_port

    def _run(self):
        local_port = self._get_local_port_to_use()
        self._effective_port = local_port
        command_line = [CONFIG["aws_cli"]]
        if self._host_config.profile:
            command_line += ["--profile", self._host_config.profile]
        if self._host_config.region:
            command_line += ["--region", self._host_config.region]
        rhost = self._local_forward_config.remote_address
        rport = self._local_forward_config.remote_port
        command_line += ["ssm", "start-session", "--target", self._instance_id,
                         "--document-name", "AWS-StartPortForwardingSessionToRemoteHost",
                         "--parameters",
                         (
                             "{"
                             f"\"host\":[\"{rhost}\"],"
                             f"\"portNumber\":[\"{rport}\"],"
                             f"\"localPortNumber\":[\"{local_port}\"]"
                             "}"
                         )]

        self._logger.debug(f"EXEC: {command_line}")
        self._external_process_exit_code = None
        self._external_process = subprocess.Popen(command_line, shell=False)
        self._logger.debug("external process started")

    def cleanup(self):
        self.is_running()


class LocalForwardGatewayController:
    def __init__(self, instance_id: str, host_config: HostConfig, local_forward_config: LocalForwardConfig):
        self._instance_id = instance_id
        self._host_config = host_config
        self._local_forward_config = local_forward_config
        self._logger = logging.getLogger(self.__class__.__name__)

        self._stopped = False
        self._server_socket: socket.socket = None
        self._inner_controller: LocalForwardSimpleController = None
        self._accept_thread: Thread = None
        self._remote_desc = f"{self._local_forward_config.remote_address}:{self._local_forward_config.remote_port}"

    def start(self):
        if self.is_running():
            return
        try:
            self._stopped = False
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind(('localhost', self._local_forward_config.local_port))
            self._server_socket.listen(10)
            self._logger.info(f"Listening on port {self._local_forward_config.local_port} -> {self._remote_desc}")
            self._accept_thread = Thread(target=self._run, daemon=False)
            self._accept_thread.start()
        except Exception as ex:
            if self._server_socket:
                self._server_socket.close()
            raise Exception(f"Failed to start port forwarding for port {self._local_forward_config.local_port}: {ex}")

    def stop(self):
        self._stopped = True
        if self._server_socket:
            execute_silently(lambda: self._server_socket.shutdown(socket.SHUT_RDWR))
        if self._inner_controller:
            self._inner_controller.stop()
        if self._accept_thread:
            self._accept_thread.join(timeout=1)
        if self._server_socket:
            execute_silently(lambda: self._server_socket.close())
        self._server_socket = None
        self._inner_controller = None
        self._accept_thread = None

    def is_running(self):
        return self._accept_thread is not None and self._accept_thread.is_alive()

    def _run(self):
        try:
            self._try_run()
        except Exception as ex:
            if not self._stopped:
                self._logger.error(f"Unhandled error on network thread: {ex}")

    def _try_run(self):
        self._logger.debug(f"Waiting connections on port {self._local_forward_config.local_port}")
        while not self._stopped:
            client_socket, addr = self._server_socket.accept()
            client_info = f"{addr[0]}:{addr[1]}"
            self._logger.info(f"Accepted connection from {client_info} -> {self._remote_desc}")
            self._handle_client_connection(client_socket, client_info)

    def _handle_client_connection(self, client_socket, client_info):
        self._start_inner_controller_if_needed()
        if self._inner_controller.is_running():
            other_local_port = self._inner_controller.get_effective_local_port()
            other_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._connect_to_controller(other_socket, ('localhost', other_local_port))
            threading.Thread(target=self._forward_data, args=(client_socket, other_socket, client_info),
                             daemon=False).start()
            threading.Thread(target=self._forward_data, args=(other_socket, client_socket), daemon=False).start()
        else:
            self._logger.warning("Failed to start SSM subprocess")
            client_socket.close()

    def _connect_to_controller(self, other_socket: socket.socket, endpoint):
        repetitions = 5
        delay = 0.250
        while True:
            try:
                return other_socket.connect(endpoint)
            except Exception as e:
                repetitions -= 1
                if repetitions == 0:
                    raise e
                time.sleep(delay)
                delay *= 2

    def _start_inner_controller_if_needed(self):
        if self._inner_controller is None:
            self._inner_controller = LocalForwardSimpleController(
                self._instance_id,
                self._host_config,
                self._local_forward_config.with_random_local_port()
            )
        if not self._inner_controller.is_running():
            self._inner_controller.start()
            time.sleep(0.5)

    # Forward data between client and server
    def _forward_data(self, source_socket: socket.socket, destination_socket: socket.socket, info: str = None):
        try:
            while True:
                data = source_socket.recv(4096)
                if not data:
                    if info:
                        self._logger.info(f"Connection closed: {info}")
                    break
                destination_socket.sendall(data)
        except Exception as e:
            self._logger.warning(f"Forwarding data: {e}")
        finally:
            execute_silently(lambda: source_socket.shutdown(socket.SHUT_RD))
            execute_silently(lambda: destination_socket.shutdown(socket.SHUT_WR))

    def cleanup(self):
        if self._inner_controller:
            self._inner_controller.cleanup()


def execute_silently(runnable):
    try:
        runnable()
    except:
        pass  # ignored


def get_free_port(host: str = "0.0.0.0") -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


# Function to read configuration from ~/.ssm_manager file
def read_config_file() -> Config:
    config_path = CONFIG["default_config_file"]
    config = Config()
    if not config.read_config_file(config_path):
        return None
    return config


def command_port_forwarding_gateway(args, config: Config):
    target = args.target
    host_config = config.find_host_config(target, allow_default=False)
    if not host_config:
        return
    if not host_config.local_forward:
        logging.error("No local forward configuration found.")
        return

    instance_id = host_config.resolve_hostname(target)
    controllers = []

    try:
        logging.info("Starting Port Forwarding Gateway")
        for local_forward in host_config.local_forward:
            controller = LocalForwardGatewayController(instance_id, host_config, local_forward)
            controllers.append(controller)
            controller.start()
            time.sleep(0.05)
        while controllers:
            time.sleep(3)
            for controller in controllers.copy():
                if not controller.is_running():
                    controllers.remove(controller)
                else:
                    controller.cleanup()
    except (KeyboardInterrupt, ApplicationTerminationException) as ex:
        logging.info(f"Operation canceled ({ex.__class__.__name__})")
    finally:
        logging.info("Port Forwarding Gateway finishing")
        time.sleep(1)
        for controller in controllers:
            controller.stop()
            time.sleep(0.05)
        logging.info("Port Forwarding Gateway finished")


def command_port_forwarding(args, config: Config):
    target = args.target
    host_config = config.find_host_config(target, allow_default=False)
    if not host_config:
        return
    if not host_config.local_forward:
        logging.error("no local forward configuration found")
        return

    instance_id = host_config.resolve_hostname(target)
    controllers = []

    try:
        logging.debug("Port Forwarding starting")
        for local_forward in host_config.local_forward:
            controller = LocalForwardSimpleController(instance_id, host_config, local_forward)
            controllers.append(controller)
            controller.start()
            time.sleep(0.05)
        while controllers:
            time.sleep(3)
            for controller in controllers.copy():
                if not controller.is_running():
                    controllers.remove(controller)
    except (KeyboardInterrupt, ApplicationTerminationException) as ex:
        logging.info(f"Operation canceled ({ex.__class__.__name__})")
    finally:
        logging.info("Port Forwarding finishing")
        time.sleep(1)
        for controller in controllers:
            controller.stop()
            time.sleep(0.05)
        logging.info("Port Forwarding finished")


# Function to start a shell session using SSM
def command_start_shell(args, config: Config):
    target = args.target
    host_config = config.find_host_config(target)

    instance_id = host_config.resolve_hostname(target)
    profile = host_config.profile
    region = host_config.region
    user = host_config.user

    command_line = [CONFIG["aws_cli"]]
    if profile:
        command_line += ["--profile", profile]
    if region:
        command_line += ["--region", region]
    command_line += ["ssm", "start-session", "--target", instance_id]

    if user:
        command_line += ["--document-name", "AWS-StartInteractiveCommand", "--parameters",
                         '{"command":["sudo su - ' + user + '"]}']

    logging.debug(f"EXEC: {command_line}")
    try:
        subprocess.run(command_line, shell=False)
    finally:
        logging.debug("remote shell session finished")


def _parse_args():
    parser = argparse.ArgumentParser(description='SSM Port Forwarding and Shell Access', prog='ssm-manager')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + CONFIG['version'])
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug output')
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Subparser for shell access
    shell_parser = subparsers.add_parser('shell', help='Connect to remote host using SSM (no SSH)')
    shell_parser.add_argument('target', help='Target instance ID or pattern from config file')

    # Subparser for port forwarding
    pf_parser = subparsers.add_parser('pf', help='Start port forwarding')
    pf_parser.add_argument('target', help='Target instance ID or pattern from config file')

    # Subparser for port forwarding gateway
    pfgw_parser = subparsers.add_parser('pfgw', help='Start port forwarding gateway',
                                        description="Port forwarding gateway starts SSM connections on demand.")
    pfgw_parser.add_argument('target', help='Target instance ID or pattern from config file')

    return parser.parse_args(), parser


def _signal_handler(signum, frame):
    if CONFIG["exit_signal"]:
        sys.exit(125)
    CONFIG["exit_signal"] = True
    raise ApplicationTerminationException("Received SIGTERM")


def main():
    signal.signal(signal.SIGTERM, _signal_handler)
    args, parser = _parse_args()
    CONFIG['debug'] = args.debug
    logging.basicConfig(level=logging.DEBUG if CONFIG["debug"] else logging.INFO)
    try:
        if args.command:
            config = read_config_file()
            if not config:
                return 1
            if args.command == 'shell':
                return command_start_shell(args, config)
            elif args.command == 'pf':
                return command_port_forwarding(args, config)
            elif args.command == 'pfgw':
                return command_port_forwarding_gateway(args, config)
        parser.print_help()
        return 1
    except (KeyboardInterrupt, ApplicationTerminationException) as ex:
        logging.info(f"Operation Interrupted ({ex.__class__.__name__})")
        return 127
    except Exception as e:
        logging.error(f"{e}")
        if CONFIG["debug"]:
            traceback.print_exc()
        return 126


if __name__ == '__main__':
    ret = main()
    sys.exit(ret)
