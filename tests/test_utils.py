import socket

import pytest

from ssm_manager import (
    SHUTDOWN,
    configure_tcp_socket,
    delay,
    execute_silently,
    get_free_port,
)


class TestExecuteSilently:
    def test_function_raises(self):
        def failing():
            raise ValueError("boom")

        execute_silently(failing)

    def test_function_succeeds(self):
        result = []

        def working():
            result.append(42)

        execute_silently(working)
        assert result == [42]


class TestGetFreePort:
    def test_returns_valid_port(self):
        port = get_free_port()
        assert isinstance(port, int)
        assert 0 < port < 65536

    def test_port_is_actually_free(self):
        port = get_free_port()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("0.0.0.0", port))
            s.close()


class TestConfigureTcpSocket:
    def test_sets_socket_options(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        configure_tcp_socket(sock)
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF) >= 131072
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF) >= 131072
        assert sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY) == 1
        sock.close()


class TestDelay:
    def test_delay_returns_true_when_not_shutdown(self):
        assert delay(0.001) is True

    def test_delay_returns_false_when_shutdown(self):
        SHUTDOWN.set()
        try:
            assert delay(0.001) is False
        finally:
            SHUTDOWN.clear()