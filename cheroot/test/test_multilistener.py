"""Tests for the multi-listener HTTP server."""

import socket
import threading
import time

import pytest

import requests

from ..server import MultiListenerHTTPServer
from ..testing import EPHEMERAL_PORT
from ..wsgi import Gateway_10


LOOPBACK_IP = '127.0.0.1'
THREAD_WAIT_TIMEOUT = 5.0


def _get_free_port():
    """Return a currently free TCP port on the loopback interface."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((LOOPBACK_IP, EPHEMERAL_PORT))
        return sock.getsockname()[1]


def _wait_for_thread_count(expected):
    """Wait until no extra threads are running, then return the count."""
    deadline = time.monotonic() + THREAD_WAIT_TIMEOUT
    while time.monotonic() < deadline:
        count = threading.active_count()
        if count <= expected:
            return count
        time.sleep(0.05)
    return threading.active_count()


def _hello_wsgi_app(environ, start_response):
    """Respond with a plain greeting."""
    start_response('200 OK', [('Content-Type', 'text/plain')])
    return [b'Hello, world!']


def _make_server(**kwargs):
    """Create a multi-listener server with a tiny thread pool."""
    kwargs.setdefault('minthreads', 2)
    return MultiListenerHTTPServer(Gateway_10, **kwargs)


def _prepare_wsgi_server(server, ports):
    """Add TCP listeners for the ports and prepare the server."""
    for port in ports:
        server.add_listener((LOOPBACK_IP, port))
    server.prepare()
    for child in server.servers:
        child.wsgi_app = _hello_wsgi_app


def _assert_port_bindable(port):
    """Check that the port is free, i.e. no listener is holding it."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((LOOPBACK_IP, port))


def test_prepare_rolls_back_when_a_listener_fails_to_bind():
    """A failing listener must not leave half-started listeners behind."""
    first_port = _get_free_port()
    second_port = _get_free_port()
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind((LOOPBACK_IP, EPHEMERAL_PORT))
    blocker.listen(1)
    occupied_port = blocker.getsockname()[1]

    baseline_threads = threading.active_count()
    server = _make_server()
    server.add_listener((LOOPBACK_IP, first_port))
    server.add_listener((LOOPBACK_IP, second_port))
    server.add_listener((LOOPBACK_IP, occupied_port))

    try:
        with pytest.raises(OSError):
            server.prepare()

        # Nothing may be left running: the first two listeners were
        # rolled back, so their ports are free again and no worker
        # threads survive.
        assert not server.prepared
        assert not server.ready
        assert server.servers == ()
        _assert_port_bindable(first_port)
        _assert_port_bindable(second_port)
        assert _wait_for_thread_count(baseline_threads) == baseline_threads

        # Once the conflicting port is released, the very same server
        # object can be prepared again.
        blocker.close()
        server.prepare()
        try:
            assert server.prepared
            assert len(server.servers) == 3
            assert server.bind_addrs == (
                (LOOPBACK_IP, first_port),
                (LOOPBACK_IP, second_port),
                (LOOPBACK_IP, occupied_port),
            )
        finally:
            server.stop()
        assert _wait_for_thread_count(baseline_threads) == baseline_threads
    finally:
        blocker.close()


def test_serve_all_listeners_and_reprepare_after_stop():
    """All listeners serve requests; stop() allows preparing again."""
    ports = [_get_free_port() for _ in range(3)]
    baseline_threads = threading.active_count()
    server = _make_server()
    _prepare_wsgi_server(server, ports)

    # Each listener is registered exactly once with its selector.
    for child in server.servers:
        assert len(child._connections._selector) == 1

    serve_thread = threading.Thread(target=server.serve, daemon=True)
    serve_thread.start()
    try:
        for port in ports:
            response = requests.get(
                f'http://{LOOPBACK_IP}:{port}/',
                timeout=20,
            )
            assert response.status_code == 200
            assert response.text == 'Hello, world!'
    finally:
        server.stop()
        serve_thread.join(THREAD_WAIT_TIMEOUT)

    assert not serve_thread.is_alive()
    assert not server.prepared
    assert _wait_for_thread_count(baseline_threads) == baseline_threads

    # The server can be prepared and stopped again without duplicating
    # listener registrations.
    server.prepare()
    for child in server.servers:
        child.wsgi_app = _hello_wsgi_app
    try:
        assert len(server.servers) == 3
        for child in server.servers:
            assert len(child._connections._selector) == 1
    finally:
        server.stop()
    assert _wait_for_thread_count(baseline_threads) == baseline_threads


def test_external_socket_ownership_is_explicit():
    """Borrowed sockets survive stop(); owned ones are closed."""
    borrowed = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    borrowed.bind((LOOPBACK_IP, EPHEMERAL_PORT))
    owned = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    owned.bind((LOOPBACK_IP, EPHEMERAL_PORT))

    server = _make_server()
    server.add_socket(borrowed, owns_socket=False)
    server.add_socket(owned, owns_socket=True)
    server.prepare()
    try:
        assert server.prepared
        assert len(server.servers) == 2
    finally:
        server.stop()

    assert borrowed.fileno() != -1, 'borrowed socket must stay open'
    assert owned.fileno() == -1, 'owned socket must be closed'

    # Re-preparing fails on the consumed (owned, now closed) socket
    # without harming the borrowed one.
    with pytest.raises(RuntimeError, match='closed socket'):
        server.prepare()
    assert borrowed.fileno() != -1

    # A server holding only the borrowed socket re-prepares fine.
    borrowed_server = _make_server()
    borrowed_server.add_socket(borrowed, owns_socket=False)
    borrowed_server.prepare()
    borrowed_server.stop()
    assert borrowed.fileno() != -1
    borrowed.close()


def test_add_socket_requires_ownership():
    """The ownership of external sockets must be stated explicitly."""
    server = _make_server()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(TypeError):
            server.add_socket(sock)
    finally:
        sock.close()


def test_prepare_rejects_invalid_ssl_adapter_before_binding():
    """The TLS adapter is checked before any socket is bound."""
    port = _get_free_port()

    server = _make_server(ssl_adapter=object())
    server.add_listener((LOOPBACK_IP, port))
    with pytest.raises(TypeError, match='ssl_adapter'):
        server.prepare()
    _assert_port_bindable(port)

    class ContextlessAdapter:
        context = None

        def wrap(self, sock):
            return sock, {}

        def makefile(self, sock, mode='r', bufsize=-1):
            return sock.makefile(mode, bufsize)

    server = _make_server(ssl_adapter=ContextlessAdapter())
    server.add_listener((LOOPBACK_IP, port))
    with pytest.raises(ValueError, match='TLS context'):
        server.prepare()
    _assert_port_bindable(port)


def test_prepare_requires_listeners():
    """Preparing a server without listeners is an error."""
    server = _make_server()
    with pytest.raises(RuntimeError, match='without listeners'):
        server.prepare()


def test_serve_requires_prepare():
    """Serving requires a successful prepare() first."""
    server = _make_server()
    server.add_listener((LOOPBACK_IP, EPHEMERAL_PORT))
    with pytest.raises(RuntimeError, match='prepared before serving'):
        server.serve()


def test_cannot_add_listeners_while_prepared():
    """Listeners can only be added before prepare()."""
    server = _make_server()
    server.add_listener((LOOPBACK_IP, EPHEMERAL_PORT))
    server.prepare()
    try:
        with pytest.raises(RuntimeError, match='cannot be added'):
            server.add_listener((LOOPBACK_IP, EPHEMERAL_PORT))
    finally:
        server.stop()


def test_double_prepare_is_rejected():
    """Preparing twice without stopping is an error."""
    server = _make_server()
    server.add_listener((LOOPBACK_IP, EPHEMERAL_PORT))
    server.prepare()
    try:
        with pytest.raises(RuntimeError, match='already prepared'):
            server.prepare()
    finally:
        server.stop()


def test_gateway_is_shared_by_all_listeners():
    """All per-listener servers use the gateway given to the group."""
    server = _make_server()
    server.add_listener((LOOPBACK_IP, EPHEMERAL_PORT))
    server.add_listener((LOOPBACK_IP, EPHEMERAL_PORT))
    server.prepare()
    try:
        for child in server.servers:
            assert child.gateway is Gateway_10
    finally:
        server.stop()
