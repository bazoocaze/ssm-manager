import socket
import subprocess
import threading
import time
import sys

# Global configuration dictionary
CONFIG = {
    'aws_cli_command': 'aws ssm start-session --target {instance_id} --document-name AWS-StartPortForwardingSession --parameters "portNumber={local_port},localAddress={local_address}"',
    'shell_command': 'aws ssm start-session --target {instance_id}',
    'local_port': 2222,
    'local_address': '127.0.0.1',
    'instance_id': 'i-0123456789abcdef0',  # Replace with your instance ID
}

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
def start_shell():
    aws_command = CONFIG['shell_command'].format(instance_id=CONFIG['instance_id'])
    subprocess.run(aws_command, shell=True)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python main.py <command>")
        print("Commands:")
        print("  pf     Start port forwarding gateway")
        print("  shell  Connect to remote host using SSM (no SSH)")
        sys.exit(1)

    command = sys.argv[1]

    if command == 'pf':
        start_gateway()
    elif command == 'shell':
        start_shell()
    else:
        print(f"Unknown command: {command}")
        print("Available commands: pf, shell")
        sys.exit(1)
