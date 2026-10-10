import socket
import threading
import time

import pytest

import ssm_manager
from ssm_manager import (
    HostConfig,
    LocalForwardConfig,
    LocalForwardGatewayController,
)


class FakeInnerController:
    def __init__(self, running=True, port=1234):
        self._running = running
        self._port = port

    def is_running(self):
        return self._running

    def get_effective_local_port(self):
        return self._port

    def stop(self):
        pass


def make_gateway(inner=None):
    lf = LocalForwardConfig()
    lf.parse_line(1, "localforward", "15432 127.0.0.1:5432")
    gw = LocalForwardGatewayController("i-test", HostConfig("i-test"), lf)
    gw._inner_controller = inner if inner is not None else FakeInnerController()
    return gw


class FakeClock:
    def __init__(self):
        self.t = 0.0


class FakeMonotonic:
    def __init__(self, clock):
        self._clock = clock

    def monotonic(self):
        return self._clock.t


class FakeSocket:
    """connect() is refused until the fake clock reaches `ready_at`; records attempt times."""

    def __init__(self, clock, ready_at):
        self.clock = clock
        self.ready_at = ready_at
        self.attempts = []

    def connect(self, endpoint):
        self.attempts.append(round(self.clock.t, 3))
        if self.clock.t < self.ready_at:
            raise ConnectionRefusedError("not ready")
        return None


class TestConnectToController:
    def _install_fake_clock(self, monkeypatch):
        clock = FakeClock()
        monkeypatch.setattr(ssm_manager, "time", FakeMonotonic(clock), raising=False)
        monkeypatch.setattr(ssm_manager, "delay", lambda seconds: setattr(clock, "t", clock.t + seconds))
        return clock

    def test_polls_at_fixed_short_interval(self, monkeypatch):
        clock = self._install_fake_clock(monkeypatch)
        gw = make_gateway()
        # port only becomes available at 17s - well past the old 16s exponential gap
        sock = FakeSocket(clock, ready_at=17.0)

        gw._connect_to_controller(sock, ("127.0.0.1", 0))

        # succeeds on the first attempt at/after the port is ready...
        assert sock.attempts[-1] == 17.0
        # ...and every retry is spaced by a small fixed interval (no exponential 16s gap)
        gaps = [round(b - a, 3) for a, b in zip(sock.attempts, sock.attempts[1:])]
        assert gaps
        assert all(g == pytest.approx(0.5) for g in gaps)

    def test_fails_fast_when_inner_process_died(self, monkeypatch):
        clock = self._install_fake_clock(monkeypatch)
        gw = make_gateway(FakeInnerController(running=False))
        sock = FakeSocket(clock, ready_at=999)

        with pytest.raises(Exception, match="SSM process died"):
            gw._connect_to_controller(sock, ("127.0.0.1", 0))

        assert clock.t == 0.0       # no waiting at all
        assert sock.attempts == []  # never even tried to connect

    def test_raises_when_stopped(self, monkeypatch):
        self._install_fake_clock(monkeypatch)
        gw = make_gateway()
        gw._stopped = True

        with pytest.raises(Exception, match="canceled"):
            gw._connect_to_controller(FakeSocket(FakeClock(), 0), ("127.0.0.1", 0))

    def test_times_out_after_budget(self, monkeypatch):
        clock = self._install_fake_clock(monkeypatch)
        gw = make_gateway()
        sock = FakeSocket(clock, ready_at=999)

        with pytest.raises(ConnectionRefusedError):
            gw._connect_to_controller(sock, ("127.0.0.1", 0))

        assert clock.t >= 60.0

    def test_connects_to_real_listener_that_starts_late(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        # bound but NOT listening: connect() is refused until listen() runs
        timer = threading.Timer(0.6, srv.listen, args=(5,))
        timer.start()

        gw = make_gateway()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.settimeout(5)
        started = time.monotonic()
        try:
            gw._connect_to_controller(sock, ("127.0.0.1", port))
            elapsed = time.monotonic() - started
            conn, _ = srv.accept()  # proves the tunnel socket really connected
            conn.close()
            assert elapsed >= 0.5
            assert elapsed < 3.0    # prompt poll, not a long backoff
        finally:
            timer.cancel()
            sock.close()
            srv.close()


class TestHandleClientConnection:
    def test_closes_client_and_swallows_error_when_connect_fails(self, monkeypatch):
        gw = make_gateway(FakeInnerController(running=True))
        monkeypatch.setattr(gw, "_start_inner_controller_if_needed", lambda: None)

        def fail_connect(other_socket, endpoint):
            raise ConnectionRefusedError("boom")

        monkeypatch.setattr(gw, "_connect_to_controller", fail_connect)

        client, peer = socket.socketpair()
        try:
            # must not raise: the gateway stays alive for the next connection
            gw._handle_client_connection(client, "127.0.0.1:55555")
            peer.settimeout(1.0)
            assert peer.recv(1) == b""  # client socket was closed
        finally:
            client.close()
            peer.close()
