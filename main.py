import socket
import subprocess
import threading
import time
import sys
import argparse
import os
import configparser
import fnmatch

# Global configuration dictionary
CONFIG = {
    'aws_cli_command': 'aws ssm start-session --target {instance_id} --document-name AWS-StartPortForwardingSession --parameters "portNumber={local_port},localAddress={local_address}"',
    'shell_command': 'aws ssm start-session --target {instance_id}',
    'local_port': 2222,
    'local_address': '127.0.0.1',
    'instance_id': 'i-0123456789abcdef0',  # Replace with your instance ID
}

# Function to read configuration from ~/.ssm_manager file
def read_config_file():
    config_path = os.path.expanduser('~/.ssm_manager')
    if not os.path.exists(config_path):
        return None

    config = configparser.ConfigParser()
    config.read(config_path)
    return config

# Function to find the first matching section for a given host pattern
def find_first_match(config, target):
    for section in config.sections():
        if fnmatch.fnmatch(target, section):
            return section
    return None

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

# Function to start a shell session using SSM
def start_shell(target):
    config = read_config_file()

    if config:
        matched_section = find_first_match(config, target)
        if matched_section:
            section = config[matched_section]
            instance_id = section.get('Hostname', target)
            profile = section.get('Profile')
            region = section.get('Region')

            aws_command = CONFIG['shell_command'].format(instance_id=instance_id)

            if profile:
                aws_command = f"aws --profile {profile} {aws_command}"
            if region:
                aws_command = f"aws --region {region} {aws_command}"

        else:
            # Fallback to original behavior
            aws_command = CONFIG['shell_command'].format(instance_id=target)

    else:
        # No config file found, use the target directly
        aws_command = CONFIG['shell_command'].format(instance_id=target)

    subprocess.run(aws_command, shell=True)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SSM Port Forwarding and Shell Access')
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Subparser for port forwarding
    pf_parser = subparsers.add_parser('pf', help='Start port forwarding gateway')

    # Subparser for shell access
    shell_parser = subparsers.add_parser('shell', help='Connect to remote host using SSM (no SSH)')
    shell_parser.add_argument('target', help='Target instance ID or pattern from config file')

    args = parser.parse_args()

    if args.command == 'pf':
        start_gateway()
    elif args.command == 'shell':
        start_shell(args.target)
    else:
        parser.print_help()
