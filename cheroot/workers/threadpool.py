"""A thread-based worker pool.

.. spelling::

   joinable
"""

import collections
import contextlib
import logging
import queue
import socket
import threading
import time
import warnings

from jaraco.functools import pass_none


__all__ = ('SharedExecutionQuota', 'ThreadPool', 'WorkerThread')


class TrueyZero:
    """Object which equals and does math like the integer 0 but evals True."""

    def __add__(self, other):
        return other

    def __radd__(self, other):
        return other


trueyzero = TrueyZero()

_SHUTDOWNREQUEST = object()

_EXECUTION_ABORTED = object()


class _EndpointQuota:
    """Bookkeeping for a single endpoint registered with a quota."""

    __slots__ = ('reserved', 'reserved_in_use', 'shared_in_use')

    def __init__(self, reserved):
        self.reserved = reserved
        self.reserved_in_use = 0
        self.shared_in_use = 0


class _ExecutionPermit:
    """A token representing one acquired execution slot."""

    __slots__ = ('endpoint', 'shared')

    def __init__(self, endpoint, shared):
        self.endpoint = endpoint
        self.shared = shared


class SharedExecutionQuota:
    """Execution capacity shared between multiple server endpoints.

    A single quota instance may be shared by several
    :py:class:`~cheroot.server.HTTPServer` instances (endpoints) — for
    example, a data endpoint and a management endpoint listening on
    different ports. Each endpoint registers a number of *reserved*
    execution slots that are guaranteed to remain available to that
    endpoint only — other endpoints can never borrow them. On top of
    the reserved slots, all endpoints compete for a common pool of
    *shared* slots, allowing a busy endpoint to borrow spare capacity
    whenever the other endpoints are idle.

    A slot is only held while a connection is actively being executed
    by a worker thread; queued connections do not consume any
    capacity. Slots are returned when a request finishes (keep-alive
    connections re-enter scheduling for every request instead of
    holding their slot), when a connection is closed, when an error
    occurs, and when the worker pool is shrunk or stopped.
    """

    def __init__(self, shared=0):
        """Initialize the shared execution quota.

        Args:
            shared (int): number of execution slots that any registered
                endpoint may borrow on top of its reserved slots

        :raises ValueError: if the shared slot count is invalid
        """
        if shared < 0:
            raise ValueError(f'shared={shared!s} must be >= 0')
        self._shared_total = shared
        self._shared_in_use = 0
        self._endpoints = {}
        self._condition = threading.Condition()

    @property
    def shared(self):
        """Total number of shared execution slots."""
        return self._shared_total

    @property
    def shared_in_use(self):
        """Number of shared execution slots currently in use."""
        with self._condition:
            return self._shared_in_use

    def register(self, endpoint, reserved=0):
        """Register an endpoint, reserving execution slots for it.

        Args:
            endpoint: hashable identifier of the endpoint, typically
                the :py:class:`~cheroot.server.HTTPServer` instance
            reserved (int): number of execution slots guaranteed to
                remain available to this endpoint only

        :raises ValueError: if the endpoint is already registered or
            the reserved slot count is invalid
        """
        if reserved < 0:
            raise ValueError(f'reserved={reserved!s} must be >= 0')
        with self._condition:
            if endpoint in self._endpoints:
                raise ValueError(
                    f'Endpoint {endpoint!r} is already registered',
                )
            self._endpoints[endpoint] = _EndpointQuota(reserved)
            self._condition.notify_all()

    def unregister(self, endpoint):
        """Remove an endpoint, waking up its pending workers.

        Permits that are still held by the endpoint remain valid and
        keep being accounted for until they are released.
        """
        with self._condition:
            self._endpoints.pop(endpoint, None)
            self._condition.notify_all()

    def reserved(self, endpoint):
        """Return the number of slots reserved for an endpoint."""
        with self._condition:
            state = self._endpoints.get(endpoint)
            return 0 if state is None else state.reserved

    def in_use(self, endpoint):
        """Return the number of slots currently used by an endpoint."""
        with self._condition:
            state = self._endpoints.get(endpoint)
            if state is None:
                return 0
            return state.reserved_in_use + state.shared_in_use

    def acquire(self, endpoint):
        """Acquire an execution permit for an endpoint.

        Blocks until a slot is available. Reserved slots of the
        endpoint are used first; once they are exhausted, shared slots
        are borrowed.

        Returns:
            an execution permit to be passed to :py:meth:`release`,
            or :py:data:`None` if the endpoint is not registered
            (anymore), signaling the caller to abort
        """
        with self._condition:
            while True:
                state = self._endpoints.get(endpoint)
                if state is None:
                    return None
                if state.reserved_in_use < state.reserved:
                    state.reserved_in_use += 1
                    return _ExecutionPermit(endpoint, shared=False)
                if self._shared_in_use < self._shared_total:
                    self._shared_in_use += 1
                    state.shared_in_use += 1
                    return _ExecutionPermit(endpoint, shared=True)
                self._condition.wait()

    def release(self, permit):
        """Return a previously acquired execution permit."""
        with self._condition:
            state = self._endpoints.get(permit.endpoint)
            if permit.shared:
                self._shared_in_use -= 1
                if state is not None:
                    state.shared_in_use -= 1
            elif state is not None:
                state.reserved_in_use -= 1
            self._condition.notify_all()


class WorkerThread(threading.Thread):
    """Thread which continuously polls a Queue for Connection objects.

    Due to the timing issues of polling a Queue, a WorkerThread does not
    check its own 'ready' flag after it has started. To stop the thread,
    it is necessary to stick a _SHUTDOWNREQUEST object onto the Queue
    (one for each running WorkerThread).
    """

    conn = None
    """The current connection pulled off the Queue, or None."""

    server = None
    """The HTTP Server which spawned this thread, and which owns the
    Queue and is placing active connections into it."""

    ready = False
    """A simple flag for the calling server to know when this thread
    has begun polling the Queue."""

    def __init__(self, server):
        """Initialize WorkerThread instance.

        Args:
            server (cheroot.server.HTTPServer): web server object
                receiving this request
        """
        self.ready = False
        self.server = server

        self.requests_seen = 0
        self.bytes_read = 0
        self.bytes_written = 0
        self.start_time = None
        self.work_time = 0
        self.stats = {
            'Requests': lambda s: (
                self.requests_seen
                + (
                    (self.start_time is None and trueyzero)
                    or self.conn.requests_seen
                )
            ),
            'Bytes Read': lambda s: (
                self.bytes_read
                + (
                    (self.start_time is None and trueyzero)
                    or self.conn.rfile.bytes_read
                )
            ),
            'Bytes Written': lambda s: (
                self.bytes_written
                + (
                    (self.start_time is None and trueyzero)
                    or self.conn.wfile.bytes_written
                )
            ),
            'Work Time': lambda s: (
                self.work_time
                + (
                    (self.start_time is None and trueyzero)
                    or time.time() - self.start_time
                )
            ),
            'Read Throughput': lambda s: (
                s['Bytes Read'](s) / (s['Work Time'](s) or 1e-6)
            ),
            'Write Throughput': lambda s: (
                s['Bytes Written'](s) / (s['Work Time'](s) or 1e-6)
            ),
        }
        threading.Thread.__init__(self)

    def run(self):
        """Set up incoming HTTP connection processing loop.

        This is the thread's entry-point. It performs lop-layer
        exception handling and interrupt processing.
        :exc:`KeyboardInterrupt` and :exc:`SystemExit` bubbling up
        from the inner-layer code constitute a global server interrupt
        request. When they happen, the worker thread exits.

        :raises BaseException: when an unexpected non-interrupt
                               exception leaks from the inner layers

        # noqa: DAR401 KeyboardInterrupt SystemExit
        """
        self.server.stats['Worker Threads'][self.name] = self.stats
        self.ready = True
        try:
            self._process_connections_until_interrupted()
        except (KeyboardInterrupt, SystemExit) as interrupt_exc:
            interrupt_cause = interrupt_exc.__cause__ or interrupt_exc
            self.server.error_log(
                f'Setting the server interrupt flag to {interrupt_cause!r}',
                level=logging.DEBUG,
            )
            self.server.interrupt = interrupt_cause
        except BaseException as underlying_exc:
            # NOTE: This is the last resort logging with the last dying breath
            # NOTE: of the worker. It is only reachable when exceptions happen
            # NOTE: in the `finally` branch of the internal try/except block.
            self.server.error_log(
                'A fatal exception happened. Setting the server interrupt flag'
                f' to {underlying_exc!r} and giving up.'
                '\N{NEW LINE}\N{NEW LINE}'
                'Please, report this on the Cheroot tracker at '
                '<https://github.com/cherrypy/cheroot/issues/new/choose>, '
                'providing a full reproducer with as much context and details as possible.',
                level=logging.CRITICAL,
                traceback=True,
            )
            self.server.interrupt = underlying_exc
            raise
        finally:
            self.ready = False

    def _process_connections_until_interrupted(self):
        """Process incoming HTTP connections in an infinite loop.

        Retrieves incoming connections from thread pool, processing
        them one by one.

        :raises SystemExit: on the internal requests to stop the
                            server instance
        """
        while True:
            conn = self.server.requests.get()
            if conn is _SHUTDOWNREQUEST:
                return

            self.conn = conn
            is_stats_enabled = self.server.stats['Enabled']
            if is_stats_enabled:
                self.start_time = time.time()
            keep_conn_open = False
            permit = self._acquire_execution_permit()
            if permit is _EXECUTION_ABORTED:
                # The endpoint was unregistered from the shared
                # execution quota (the server is shutting down) while
                # waiting for a slot — drop the connection.
                conn.close()
                if is_stats_enabled:
                    self.start_time = None
                self.conn = None
                continue
            try:  # noqa: WPS243 check "Found too long `finally` block: 3 > 2"
                keep_conn_open = conn.communicate()
            except ConnectionError as connection_error:
                keep_conn_open = False  # Drop the connection cleanly
                self.server.error_log(
                    'Got a connection error while handling a '
                    f'connection from {conn.remote_addr!s}:'
                    f'{conn.remote_port!s} ({connection_error!s})',
                    level=logging.INFO,
                )
                continue
            except (KeyboardInterrupt, SystemExit) as shutdown_request:
                # Shutdown request
                keep_conn_open = False  # Drop the connection cleanly
                self.server.error_log(
                    'Got a server shutdown request while handling a '
                    f'connection from {conn.remote_addr!s}:'
                    f'{conn.remote_port!s} ({shutdown_request!s})',
                    level=logging.DEBUG,
                )
                raise SystemExit(
                    str(shutdown_request),
                ) from shutdown_request
            except BaseException as unhandled_error:
                # NOTE: Only a shutdown request should bubble up to the
                # NOTE: external cleanup code. Otherwise, this thread dies.
                # NOTE: If this were to happen, the threadpool would still
                # NOTE: list a dead thread without knowing its state. And
                # NOTE: the calling code would fail to schedule processing
                # NOTE: of new requests.
                self.server.error_log(
                    'Unhandled error while processing an incoming '
                    f'connection {unhandled_error!r}',
                    level=logging.ERROR,
                    traceback=True,
                )
                continue  # Prevent the thread from dying
            finally:
                # NOTE: Any exceptions coming from within `finally` may
                # NOTE: kill the thread, causing the threadpool to only
                # NOTE: contain references to dead threads rendering the
                # NOTE: server defunct, effectively meaning a DoS.
                # NOTE: Ideally, things called here should process
                # NOTE: everything recoverable internally. Any unhandled
                # NOTE: errors will bubble up into the outer try/except
                # NOTE: block. They will be treated as fatal and turned
                # NOTE: into server shutdown requests and then reraised
                # NOTE: unconditionally.
                self._release_execution_permit(permit)
                if keep_conn_open:
                    self.server.put_conn(conn)
                else:
                    conn.close()
                if is_stats_enabled:
                    self.requests_seen += conn.requests_seen
                    self.bytes_read += conn.rfile.bytes_read
                    self.bytes_written += conn.wfile.bytes_written
                    self.work_time += time.time() - self.start_time
                    self.start_time = None
                self.conn = None

    def _acquire_execution_permit(self):
        """Acquire an execution permit from the shared quota, if any.

        Blocks until a slot is available for this worker's endpoint.
        Queued and waiting connections do not count as executing.
        """
        quota = getattr(self.server, 'execution_quota', None)
        if quota is None:
            return None
        permit = quota.acquire(self.server)
        return _EXECUTION_ABORTED if permit is None else permit

    def _release_execution_permit(self, permit):
        """Return a previously acquired execution permit to the quota."""
        if permit is None or permit is _EXECUTION_ABORTED:
            return
        self.server.execution_quota.release(permit)


class ThreadPool:
    """A Request Queue for an HTTPServer which pools threads.

    ThreadPool objects must provide min, get(), put(obj), start()
    and stop(timeout) attributes.
    """

    def __init__(  # pylint: disable=too-many-positional-arguments
        self,
        server,
        min=10,
        max=-1,
        accepted_queue_size=-1,
        accepted_queue_timeout=10,
    ):
        """Initialize HTTP requests queue instance.

        Args:
            server (cheroot.server.HTTPServer): web server object
                receiving this request
            min (int): minimum number of worker threads
            max (int): maximum number of worker threads (-1/inf for no max)
            accepted_queue_size (int): maximum number of active
                requests in queue
            accepted_queue_timeout (int): timeout for putting request
                into queue

        :raises ValueError: if the min/max values are invalid
        :raises TypeError: if the max is not an integer or inf
        """
        if min < 1:
            raise ValueError(f'min={min!s} must be > 0')

        if max == float('inf'):
            pass
        elif not isinstance(max, int) or max == 0:
            raise TypeError(
                'Expected an integer or the infinity value for the `max` '
                f'argument but got {max!r}.',
            )
        elif max < 0:
            max = float('inf')

        if max < min:
            raise ValueError(
                f'max={max!s} must be > min={min!s} (or infinity for no max)',
            )

        self.server = server
        self.min = min
        self.max = max
        self._threads = []
        self._queue = queue.Queue(maxsize=accepted_queue_size)
        self._queue_put_timeout = accepted_queue_timeout
        self.get = self._queue.get
        self._pending_shutdowns = collections.deque()

    def start(self):
        """Start the pool of threads.

        :raises RuntimeError: if the pool is already started
        """
        if self._threads:
            raise RuntimeError('Threadpools can only be started once.')
        self.grow(self.min)

    @property
    def idle(self):  # noqa: D401; irrelevant for properties
        """Number of worker threads which are idle. Read-only."""  # noqa: D401
        idles = len([t for t in self._threads if t.conn is None])
        return max(idles - len(self._pending_shutdowns), 0)

    def put(self, obj):
        """Put request into queue.

        Args:
            obj (:py:class:`~cheroot.server.HTTPConnection`): HTTP connection
                waiting to be processed
        """
        self._queue.put(obj, block=True, timeout=self._queue_put_timeout)

    def _clear_dead_threads(self):
        # Remove any dead threads from our list
        for t in [t for t in self._threads if not t.is_alive()]:
            self._threads.remove(t)
            with contextlib.suppress(IndexError):
                self._pending_shutdowns.popleft()

    def grow(self, amount):
        """Spawn new worker threads (not above self.max)."""
        budget = max(self.max - len(self._threads), 0)
        n_new = min(amount, budget)

        workers = [self._spawn_worker() for i in range(n_new)]
        for worker in workers:
            while not worker.ready:
                time.sleep(0.1)
        self._threads.extend(workers)

    def _spawn_worker(self):
        worker = WorkerThread(self.server)
        worker.name = f'CP Server {worker.name!s}'
        worker.start()
        return worker

    def shrink(self, amount):
        """Kill off worker threads (not below self.min)."""
        # Grow/shrink the pool if necessary.
        # Remove any dead threads from our list
        amount -= len(self._pending_shutdowns)
        self._clear_dead_threads()
        if amount <= 0:
            return

        # calculate the number of threads above the minimum
        n_extra = max(len(self._threads) - self.min, 0)

        # don't remove more than amount
        n_to_remove = min(amount, n_extra)

        # put shutdown requests on the queue equal to the number of threads
        # to remove. As each request is processed by a worker, that worker
        # will terminate and be culled from the list.
        for _ in range(n_to_remove):
            self._pending_shutdowns.append(None)
            self._queue.put(_SHUTDOWNREQUEST)

    def stop(self, timeout=5):
        """Terminate all worker threads.

        Args:
            timeout (int): time to wait for threads to stop gracefully
        """
        # for compatability, negative timeouts are treated like None
        # TODO: treat negative timeouts like already expired timeouts
        if timeout is not None and timeout < 0:
            timeout = None
            warnings.warning(
                'In the future, negative timeouts to Server.stop() '
                'will be equivalent to a timeout of zero.',
                stacklevel=2,
            )

        if timeout is None:
            endtime = float('inf')
        else:
            endtime = time.time() + timeout

        # Must shut down threads here so the code that calls
        # this method can know when all threads are stopped.
        for _worker in self._threads:
            self._queue.put(_SHUTDOWNREQUEST)

        ignored_errors = (
            # Raised when start_response called >1 time w/o exc_info or
            # wsgi write is called before start_response. See cheroot#261
            RuntimeError,
            # Ignore repeated Ctrl-C. See cherrypy#691.
            KeyboardInterrupt,
        )

        for worker in self._clear_threads():
            remaining_time = timeout and endtime - time.time()
            try:
                worker.join(remaining_time)
                if worker.is_alive():
                    # Timeout exhausted; forcibly shut down the socket.
                    self._force_close(worker.conn)
                    worker.join()
            except ignored_errors:
                pass

    @staticmethod
    @pass_none
    def _force_close(conn):
        if conn.rfile.closed:
            return
        try:
            try:
                conn.socket.shutdown(socket.SHUT_RD)
            except TypeError:
                # pyOpenSSL sockets don't take an arg
                conn.socket.shutdown()
        except OSError:
            # shutdown sometimes fails (race with 'closed' check?)
            # ref #238
            pass

    def _clear_threads(self):
        """Clear self._threads and yield all joinable threads."""
        # threads = pop_all(self._threads)
        threads, self._threads[:] = self._threads[:], []
        return (
            thread
            for thread in threads
            if thread is not threading.current_thread()
        )

    @property
    def qsize(self):
        """Return the queue size."""
        return self._queue.qsize()
