"""Tests for shared execution quotas across server endpoints."""

import contextlib
import http.client
import queue
import threading
import time
from http import HTTPStatus

import pytest

import requests

from .. import connections
from ..server import Gateway, HTTPServer
from ..testing import EPHEMERAL_PORT
from ..workers.threadpool import (
    _SHUTDOWNREQUEST,
    SharedExecutionQuota,
    WorkerThread,
)
from ..wsgi import Server as WSGIServer


LOCALHOST = '127.0.0.1'
WAIT_TIMEOUT = 10.0
POLL_INTERVAL = 0.01


def _wait_for(predicate, timeout=WAIT_TIMEOUT):
    """Poll a predicate until it becomes true or the timeout expires."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(POLL_INTERVAL)
    return predicate()


class _BlockingWSGIApp:
    """WSGI app blocking each request until released, tracking load."""

    def __init__(self):
        self._lock = threading.Lock()
        self.running = 0
        self.peak = 0
        self.release = threading.Event()

    def __call__(self, environ, start_response):
        with self._lock:
            self.running += 1
            self.peak = max(self.peak, self.running)
        try:
            self.release.wait(WAIT_TIMEOUT)
            start_response('200 OK', [('Content-Type', 'text/plain')])
            return [b'busy']
        finally:
            with self._lock:
                self.running -= 1


class _RecordingWSGIApp:
    """WSGI app responding immediately and counting its invocations."""

    def __init__(self, body=b'ok'):
        self._lock = threading.Lock()
        self.calls = 0
        self._body = body

    def __call__(self, environ, start_response):
        with self._lock:
            self.calls += 1
        start_response('200 OK', [('Content-Type', 'text/plain')])
        return [self._body]


class _FailingWSGIApp:
    """WSGI app raising an error for every request."""

    def __call__(self, environ, start_response):
        raise RuntimeError('simulated application failure')


@contextlib.contextmanager
def _serving(*servers):
    """Run the given servers in background threads."""
    for server in servers:
        server.prepare()
    serve_threads = []
    for server in servers:
        serve_thread = threading.Thread(target=server.serve)
        serve_thread.daemon = True
        serve_thread.start()
        serve_threads.append(serve_thread)
    try:
        yield servers
    finally:
        for server in servers:
            server.stop()
        for serve_thread in serve_threads:
            serve_thread.join(WAIT_TIMEOUT)


def _server_url(server):
    host, port = server.bind_addr[:2]
    return f'http://{host}:{port}/'


def _async_get(url, results, index):
    """Perform a GET request storing the outcome for later inspection."""
    try:
        results[index] = requests.get(url, timeout=WAIT_TIMEOUT).status_code
    except Exception as exc:  # noqa: WPS430
        results[index] = exc


def _fire_requests(url, count):
    """Fire off ``count`` concurrent GET requests against ``url``."""
    results = [None] * count
    threads = [
        threading.Thread(
            target=_async_get,
            args=(url, results, index),
            daemon=True,
        )
        for index in range(count)
    ]
    for thread in threads:
        thread.start()
    return threads, results


def test_quota_rejects_invalid_configuration():
    """Invalid slot counts and duplicate endpoints are rejected."""
    with pytest.raises(ValueError, match='shared=-1 must be >= 0'):
        SharedExecutionQuota(shared=-1)

    quota = SharedExecutionQuota()
    with pytest.raises(ValueError, match='reserved=-1 must be >= 0'):
        quota.register('endpoint', reserved=-1)

    quota.register('endpoint', reserved=1)
    with pytest.raises(ValueError, match='already registered'):
        quota.register('endpoint', reserved=1)


def test_reserved_slots_cannot_be_borrowed():
    """An endpoint can never use another endpoint's reserved slots."""
    quota = SharedExecutionQuota(shared=0)
    quota.register('data', reserved=1)
    quota.register('admin', reserved=1)

    data_permit = quota.acquire('data')
    assert quota.in_use('data') == 1

    acquired = []
    waiter = threading.Thread(
        target=lambda: acquired.append(quota.acquire('data')),
        daemon=True,
    )
    waiter.start()
    time.sleep(0.2)
    # Still waiting: no shared slots and the reserved slot is taken:
    assert acquired == []

    # The other endpoint's reserved slot stays untouchable:
    admin_permit = quota.acquire('admin')
    assert admin_permit is not None

    quota.release(data_permit)
    waiter.join(WAIT_TIMEOUT)
    assert len(acquired) == 1

    quota.release(acquired[0])
    quota.release(admin_permit)
    assert quota.in_use('data') == 0
    assert quota.in_use('admin') == 0


def test_idle_endpoint_shared_capacity_is_borrowable():
    """A busy endpoint borrows shared slots while others are idle."""
    quota = SharedExecutionQuota(shared=2)
    quota.register('busy', reserved=1)
    quota.register('idle', reserved=1)

    permits = [quota.acquire('busy') for _ in range(3)]
    assert quota.in_use('busy') == 3
    assert quota.shared_in_use == 2

    # The idle endpoint's reserved slot remains available to it:
    idle_permit = quota.acquire('idle')
    assert idle_permit is not None
    assert quota.in_use('idle') == 1

    for permit in permits:
        quota.release(permit)
    quota.release(idle_permit)
    assert quota.shared_in_use == 0
    assert quota.in_use('busy') == 0
    assert quota.in_use('idle') == 0


def test_acquire_aborts_when_endpoint_unregistered():
    """Workers waiting for a slot abort when the endpoint goes away."""
    quota = SharedExecutionQuota(shared=0)
    quota.register('endpoint', reserved=0)

    acquired = []
    waiter = threading.Thread(
        target=lambda: acquired.append(quota.acquire('endpoint')),
        daemon=True,
    )
    waiter.start()
    time.sleep(0.2)
    quota.unregister('endpoint')

    waiter.join(WAIT_TIMEOUT)
    assert acquired == [None]


def test_prepare_registers_and_stop_unregisters_endpoint(monkeypatch):
    """prepare() registers the endpoint and stop() unregisters it."""

    class FakeSocket:
        def settimeout(self, timeout):
            pass

        def listen(self, backlog):
            pass

        def getsockname(self):
            return (LOCALHOST, EPHEMERAL_PORT)

        def close(self):
            pass

    class FakeConnectionManager:
        def __init__(self, server):
            pass

        def stop(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr(
        HTTPServer,
        'bind',
        lambda self, *args: setattr(self, 'socket', FakeSocket()),
    )
    monkeypatch.setattr(
        connections,
        'ConnectionManager',
        FakeConnectionManager,
    )

    quota = SharedExecutionQuota(shared=1)
    server = HTTPServer(
        bind_addr=(LOCALHOST, EPHEMERAL_PORT),
        gateway=Gateway,
        execution_quota=quota,
        reserved_executions=2,
    )

    server.prepare()
    assert quota.reserved(server) == 2
    assert quota.in_use(server) == 0

    server.stop()
    assert quota.reserved(server) == 0
    assert quota.shared_in_use == 0


def test_worker_threads_acquire_and_release_execution_slots():
    """Worker threads hold a slot only while executing a connection.

    Exercises the worker loop directly: slots are acquired before a
    connection is executed, released when it finishes (including on
    errors), and keep-alive connections re-enter scheduling instead
    of holding their slot.
    """
    quota = SharedExecutionQuota(shared=0)
    entered = threading.Event()
    unblock = threading.Event()
    executed = []
    executed_lock = threading.Lock()

    class FakeConnection:
        remote_addr = '127.0.0.1'
        remote_port = 0

        def __init__(self, blocking=False, keep_alive_rounds=0, failing=False):
            self.blocking = blocking
            self.keep_alive_rounds = keep_alive_rounds
            self.failing = failing
            self.closed = False

        def communicate(self):
            if self.failing:
                raise ConnectionError('simulated connection failure')
            if self.blocking:
                entered.set()
                unblock.wait(WAIT_TIMEOUT)
            with executed_lock:
                executed.append(self)
            if self.keep_alive_rounds > 0:
                self.keep_alive_rounds -= 1
                return True
            return False

        def close(self):
            self.closed = True

    class FakeServer:
        execution_quota = quota
        interrupt = None

        def __init__(self):
            self.requests = queue.Queue()
            self.stats = {'Enabled': False, 'Worker Threads': {}}

        def put_conn(self, conn):
            self.requests.put(conn)

        def error_log(self, *args, **kwargs):
            pass

    server = FakeServer()
    quota.register(server, reserved=1)
    workers = [WorkerThread(server) for _ in range(2)]
    for worker in workers:
        worker.start()

    blocking_conn = FakeConnection(blocking=True)
    keep_alive_conn = FakeConnection(keep_alive_rounds=1)
    failing_conn = FakeConnection(failing=True)
    try:
        server.requests.put(blocking_conn)
        assert entered.wait(WAIT_TIMEOUT)
        assert quota.in_use(server) == 1

        # The second worker picks the connection up but cannot start
        # executing it while the only slot is taken:
        server.requests.put(keep_alive_conn)
        time.sleep(0.2)
        assert executed == []
        assert quota.in_use(server) == 1

        unblock.set()
        # The keep-alive connection is executed, re-queued and
        # executed again, acquiring a slot per request:
        assert _wait_for(lambda: len(executed) == 3)
        assert executed == [
            blocking_conn,
            keep_alive_conn,
            keep_alive_conn,
        ]
        assert _wait_for(lambda: quota.in_use(server) == 0)

        # Errors also return the slot:
        server.requests.put(failing_conn)
        assert _wait_for(lambda: failing_conn.closed)
        assert quota.in_use(server) == 0
    finally:
        unblock.set()
        for _ in workers:
            server.requests.put(_SHUTDOWNREQUEST)
        for worker in workers:
            worker.join(WAIT_TIMEOUT)

    assert all(not worker.is_alive() for worker in workers)
    assert blocking_conn.closed
    assert keep_alive_conn.closed
    assert quota.in_use(server) == 0


def test_management_request_served_when_data_endpoint_saturated():
    """Management requests enter the handler with data capacity full.

    The data endpoint saturates its reserved slot plus all shared
    slots with blocked requests; a management request must still
    reach its handler via the management endpoint's reserved slot.
    """
    quota = SharedExecutionQuota(shared=1)
    data_app = _BlockingWSGIApp()
    admin_app = _RecordingWSGIApp(body=b'admin')

    data_server = WSGIServer(
        (LOCALHOST, EPHEMERAL_PORT),
        data_app,
        numthreads=4,
        max=4,
        execution_quota=quota,
        reserved_executions=1,
    )
    admin_server = WSGIServer(
        (LOCALHOST, EPHEMERAL_PORT),
        admin_app,
        numthreads=2,
        max=2,
        execution_quota=quota,
        reserved_executions=1,
    )

    with _serving(data_server, admin_server):
        data_url = _server_url(data_server)
        # The data endpoint may execute reserved (1) + shared (1) = 2
        # requests concurrently; the third one stays out of execution:
        threads, results = _fire_requests(data_url, count=3)
        try:
            assert _wait_for(lambda: data_app.running == 2)
            assert quota.in_use(data_server) == 2
            assert quota.shared_in_use == 1
            assert quota.in_use(admin_server) == 0

            # The management request is served even though every slot
            # the data endpoint may use is taken:
            response = requests.get(
                _server_url(admin_server),
                timeout=WAIT_TIMEOUT,
            )
            assert response.status_code == HTTPStatus.OK
            assert response.text == 'admin'
            assert admin_app.calls == 1
            assert data_app.running == 2
        finally:
            data_app.release.set()
            for thread in threads:
                thread.join(WAIT_TIMEOUT)

        assert results == [HTTPStatus.OK] * 3
        assert data_app.peak == 2
        assert _wait_for(lambda: quota.in_use(data_server) == 0)
        assert _wait_for(lambda: quota.shared_in_use == 0)
        assert quota.in_use(admin_server) == 0


def test_keep_alive_connection_releases_slot_between_requests():
    """A keep-alive connection frees its slot after each request.

    The connection re-enters scheduling (re-acquiring a slot) for
    every subsequent request instead of holding the slot forever.
    """
    quota = SharedExecutionQuota(shared=0)
    app = _RecordingWSGIApp()
    server = WSGIServer(
        (LOCALHOST, EPHEMERAL_PORT),
        app,
        numthreads=2,
        max=2,
        execution_quota=quota,
        reserved_executions=1,
    )

    with _serving(server):
        host, port = server.bind_addr[:2]
        conn = http.client.HTTPConnection(host, port, timeout=WAIT_TIMEOUT)
        try:
            for _ in range(2):
                conn.request('GET', '/')
                response = conn.getresponse()
                assert response.status == HTTPStatus.OK
                response.read()
                # The slot is returned while the connection stays open:
                assert _wait_for(lambda: quota.in_use(server) == 0)
        finally:
            conn.close()

    assert app.calls == 2


def test_quota_slot_returned_on_application_error():
    """Execution slots are returned when request processing fails."""
    quota = SharedExecutionQuota(shared=0)
    server = WSGIServer(
        (LOCALHOST, EPHEMERAL_PORT),
        _FailingWSGIApp(),
        numthreads=1,
        max=1,
        execution_quota=quota,
        reserved_executions=1,
    )

    with _serving(server):
        response = requests.get(_server_url(server), timeout=WAIT_TIMEOUT)
        assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
        assert _wait_for(lambda: quota.in_use(server) == 0)
        assert quota.shared_in_use == 0


def test_quota_accounting_survives_pool_scaling_and_shutdown():
    """Growing, shrinking and stopping the pool returns all slots."""
    quota = SharedExecutionQuota(shared=1)
    app = _BlockingWSGIApp()
    server = WSGIServer(
        (LOCALHOST, EPHEMERAL_PORT),
        app,
        numthreads=2,
        max=4,
        execution_quota=quota,
        reserved_executions=1,
    )

    with _serving(server):
        threads, results = _fire_requests(_server_url(server), count=2)
        try:
            assert _wait_for(lambda: app.running == 2)
            assert quota.in_use(server) == 2
            assert quota.shared_in_use == 1
        finally:
            app.release.set()
            for thread in threads:
                thread.join(WAIT_TIMEOUT)
        assert results == [HTTPStatus.OK] * 2
        assert _wait_for(lambda: quota.in_use(server) == 0)

        # Scaling the pool up and back down must not leak slots:
        server.requests.grow(2)
        server.requests.shrink(3)
        assert _wait_for(lambda: quota.in_use(server) == 0)

        response = requests.get(_server_url(server), timeout=WAIT_TIMEOUT)
        assert response.status_code == HTTPStatus.OK
        assert _wait_for(lambda: quota.in_use(server) == 0)

    # Stopping the server unregisters its endpoint entirely:
    assert quota.reserved(server) == 0
    assert quota.shared_in_use == 0


def test_shutdown_releases_workers_waiting_for_a_slot():
    """stop() wakes up workers blocked on a saturated quota."""
    quota = SharedExecutionQuota(shared=0)
    app = _BlockingWSGIApp()
    server = WSGIServer(
        (LOCALHOST, EPHEMERAL_PORT),
        app,
        numthreads=2,
        max=2,
        execution_quota=quota,
        reserved_executions=1,
    )

    server.prepare()
    serve_thread = threading.Thread(target=server.serve, daemon=True)
    serve_thread.start()
    try:
        threads, results = _fire_requests(_server_url(server), count=2)
        try:
            assert _wait_for(lambda: app.running == 1)
            # The second worker is now blocked waiting for a slot:
            assert quota.in_use(server) == 1

            stop_thread = threading.Thread(target=server.stop, daemon=True)
            stop_thread.start()
            # The endpoint gets unregistered, aborting the waiting
            # worker before any slot is released:
            assert _wait_for(lambda: quota.reserved(server) == 0)
        finally:
            app.release.set()
            for thread in threads:
                thread.join(WAIT_TIMEOUT)
        stop_thread.join(WAIT_TIMEOUT)
        assert not stop_thread.is_alive()
        assert results[0] == HTTPStatus.OK
    finally:
        server.stop()
        serve_thread.join(WAIT_TIMEOUT)

    assert not serve_thread.is_alive()
    assert quota.shared_in_use == 0
