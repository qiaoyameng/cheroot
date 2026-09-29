"""Tests for the multi-listener server entry point."""

import socket
import threading
import time

import pytest

import requests

from ..server import Gateway, Listener, MultiListenerServer
from ..testing import EPHEMERAL_PORT


LOOPBACK_ADDR = '127.0.0.1'


THREAD_SETTLE_TIMEOUT = 5.0


class _HelloGateway(Gateway):
    def respond(self):
        req = self.req
        req.status = b'200 OK'
        req.ensure_headers_sent()
        req.write(b'hello')


def _get_free_port():
    with socket.socket() as probe:
        probe.bind((LOOPBACK_ADDR, EPHEMERAL_PORT))
        return probe.getsockname()[1]


def _bound_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((LOOPBACK_ADDR, EPHEMERAL_PORT))
    return sock


def _assert_no_new_threads(threads_before):
    deadline = time.monotonic() + THREAD_SETTLE_TIMEOUT
    leaked = []
    while time.monotonic() < deadline:
        leaked = [
            thread
            for thread in threading.enumerate()
            if thread not in threads_before
        ]
        if not leaked:
            return
        time.sleep(0.05)
    pytest.fail(f'Leaked threads: {leaked!r}')


def _serve_in_thread(server):
    serve_thread = threading.Thread(target=server.serve, daemon=True)
    serve_thread.start()
    return serve_thread


def test_listener_requires_exactly_one_endpoint():
    """Check that a listener takes either an address or a socket."""
    with pytest.raises(ValueError, match='exactly one'):
        Listener()
    with pytest.raises(ValueError, match='exactly one'):
        Listener(
            (LOOPBACK_ADDR, EPHEMERAL_PORT),
            sock=_bound_socket(),
            owned=True,
        )


def test_listener_requires_explicit_socket_ownership():
    """Check that external sockets need an explicit ownership flag."""
    with pytest.raises(ValueError, match='ownership'):
        Listener(sock=_bound_socket())
    with pytest.raises(ValueError, match='external sockets'):
        Listener((LOOPBACK_ADDR, EPHEMERAL_PORT), owned=True)


def test_prepare_validates_ssl_adapter_before_binding():
    """Check that TLS adapters are checked before any socket is bound."""
    server = MultiListenerServer(
        listeners=[
            Listener(
                (LOOPBACK_ADDR, EPHEMERAL_PORT),
                ssl_adapter=object(),
            ),
        ],
        gateway=Gateway,
    )

    with pytest.raises(TypeError, match='ssl_adapter'):
        server.prepare()

    assert not server.ready


def test_prepare_twice_requires_stop():
    """Check that re-preparing a prepared server is rejected."""
    server = MultiListenerServer(
        listeners=[Listener((LOOPBACK_ADDR, EPHEMERAL_PORT))],
        gateway=Gateway,
    )
    server.prepare()
    try:
        with pytest.raises(RuntimeError, match='already prepared'):
            server.prepare()
    finally:
        server.stop()


def test_prepare_rolls_back_when_a_listener_fails_to_bind():
    """Check that a failing bind undoes the already prepared listeners."""
    blocker = socket.socket()
    blocker.bind((LOOPBACK_ADDR, EPHEMERAL_PORT))
    blocker.listen()
    occupied_port = blocker.getsockname()[1]

    reusable_addrs = [
        (LOOPBACK_ADDR, _get_free_port())
        for _ in range(2)
    ]
    server = MultiListenerServer(
        listeners=[
            *(Listener(addr) for addr in reusable_addrs),
            Listener((LOOPBACK_ADDR, occupied_port)),
        ],
        gateway=_HelloGateway,
    )

    threads_before = threading.enumerate()
    try:
        with pytest.raises(OSError):
            server.prepare()

        assert not server.ready

        # The rolled-back listeners must have released their ports,
        # so they can be bound again right away.
        for bind_addr in reusable_addrs:
            with socket.socket() as probe:
                probe.bind(bind_addr)

        _assert_no_new_threads(threads_before)
    finally:
        blocker.close()


def test_restart_after_releasing_blocked_port(http_request_timeout):
    """Check rollback, then a clean start once the port is released."""
    blocker = socket.socket()
    blocker.bind((LOOPBACK_ADDR, EPHEMERAL_PORT))
    blocker.listen()
    occupied_port = blocker.getsockname()[1]

    server = MultiListenerServer(
        listeners=[
            Listener((LOOPBACK_ADDR, EPHEMERAL_PORT)),
            Listener((LOOPBACK_ADDR, EPHEMERAL_PORT)),
            Listener((LOOPBACK_ADDR, occupied_port)),
        ],
        gateway=_HelloGateway,
    )

    threads_before = threading.enumerate()
    with pytest.raises(OSError):
        server.prepare()
    assert not server.ready

    # Release the occupied port: preparing again must succeed.
    blocker.close()
    server.prepare()
    assert server.ready
    assert len(server.bind_addrs) == 3

    serve_thread = _serve_in_thread(server)
    try:
        for host, port in server.bind_addrs:
            resp = requests.get(
                f'http://{host}:{port}/',
                timeout=http_request_timeout,
            )
            assert resp.status_code == 200
            assert resp.text == 'hello'
    finally:
        server.stop()
    serve_thread.join(THREAD_SETTLE_TIMEOUT)
    assert not serve_thread.is_alive()
    assert not server.ready
    _assert_no_new_threads(threads_before)

    # Preparing again after stop() must not leave stale or
    # duplicate listeners registered behind.
    server.prepare()
    try:
        assert len(server._servers) == 3
        for httpserver, _spec in server._servers:
            selector = httpserver._connections._selector
            assert len(selector) == 1
    finally:
        server.stop()
    _assert_no_new_threads(threads_before)


def test_external_socket_ownership(http_request_timeout):
    """Check that only owned external sockets are closed on stop."""
    owned_sock = _bound_socket()
    borrowed_sock = _bound_socket()
    server = MultiListenerServer(
        listeners=[
            Listener(sock=owned_sock, owned=True),
            Listener(sock=borrowed_sock, owned=False),
        ],
        gateway=_HelloGateway,
    )

    threads_before = threading.enumerate()
    server.prepare()
    serve_thread = _serve_in_thread(server)
    try:
        for host, port in server.bind_addrs:
            resp = requests.get(
                f'http://{host}:{port}/',
                timeout=http_request_timeout,
            )
            assert resp.status_code == 200
    finally:
        server.stop()
    serve_thread.join(THREAD_SETTLE_TIMEOUT)

    assert owned_sock.fileno() == -1
    assert borrowed_sock.fileno() != -1
    borrowed_sock.close()
    _assert_no_new_threads(threads_before)


def test_rollback_leaves_borrowed_socket_open():
    """Check that a failed prepare does not close borrowed sockets."""
    blocker = socket.socket()
    blocker.bind((LOOPBACK_ADDR, EPHEMERAL_PORT))
    blocker.listen()
    occupied_port = blocker.getsockname()[1]

    borrowed_sock = _bound_socket()
    server = MultiListenerServer(
        listeners=[
            Listener(sock=borrowed_sock, owned=False),
            Listener((LOOPBACK_ADDR, occupied_port)),
        ],
        gateway=Gateway,
    )

    try:
        with pytest.raises(OSError):
            server.prepare()

        assert not server.ready
        assert borrowed_sock.fileno() != -1
    finally:
        blocker.close()
        borrowed_sock.close()
