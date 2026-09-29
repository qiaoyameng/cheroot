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


__all__ = ('ThreadPool', 'WorkerThread')


class TrueyZero:
    """Object which equals and does math like the integer 0 but evals True."""

    def __add__(self, other):
        return other

    def __radd__(self, other):
        return other


trueyzero = TrueyZero()

_SHUTDOWNREQUEST = object()


class WorkerThread(threading.Thread):
    """Thread which continuously polls a Queue for Connection objects.

    Due to the timing issues of polling a Queue, a WorkerThread does not
    check its own 'ready' flag after it has started. To stop the thread,
    it is necessary to stick a _SHUTDOWNREQUEST object onto the Queue
    (one for each running WorkerThread). The pool may also hand back
    _SHUTDOWNREQUEST on its own when an idle worker is retired after
    exceeding the pool's idle timeout.
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


class ThreadPool:
    """A Request Queue for an HTTPServer which pools threads.

    ThreadPool objects must provide min, get(), put(obj), start()
    and stop(timeout) attributes.

    The pool scales automatically between ``min`` and ``max`` threads:
    incoming bursts of connections spawn extra workers (up to ``max``),
    and workers that stay idle for longer than ``idle_timeout`` seconds
    retire themselves, never going below ``min`` threads. Idle-time is
    measured with a monotonic clock, so wall-clock adjustments do not
    affect the retirement decisions.
    """

    def __init__(  # pylint: disable=too-many-positional-arguments
        self,
        server,
        min=10,
        max=-1,
        accepted_queue_size=-1,
        accepted_queue_timeout=10,
        idle_timeout=None,
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
            idle_timeout (int): seconds an idle worker waits for work
                before retiring (None to keep workers alive forever)

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

        if idle_timeout is not None and idle_timeout < 0:
            raise ValueError(f'idle_timeout={idle_timeout!s} must be >= 0')

        self.server = server
        self.min = min
        self.max = max
        self.idle_timeout = idle_timeout
        self._threads = []
        self._queue = queue.Queue(maxsize=accepted_queue_size)
        self._queue_put_timeout = accepted_queue_timeout
        self._pending_shutdowns = collections.deque()
        # Serializes every decision that changes the number of workers
        # (manual grow/shrink, backlog-driven growth, idle retirement)
        # so concurrent deciders cannot over- or under-shoot the bounds.
        self._membership_lock = threading.Lock()
        # Monotonic clock used for all idle/shutdown timing. Kept as an
        # instance attribute so tests can inject a fake clock.
        self._monotonic = time.monotonic
        # Upper bound for a single blocking wait on the queue. None means
        # "wait for the whole remaining idle budget at once"; tests lower
        # it so a fake clock can be observed advancing in real time.
        self._idle_poll_interval = None

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

    def get(self):
        """Return the next queued connection to process.

        Blocks until a connection is available or the pool decides that
        the calling worker should terminate, in which case the
        ``_SHUTDOWNREQUEST`` sentinel is returned. A worker is asked to
        terminate either because the pool is stopping or—when
        ``idle_timeout`` is set—because it has been idle for longer than
        the configured timeout and the pool can spare it.
        """
        if self.idle_timeout is None:
            return self._queue.get()

        deadline = self._monotonic() + self.idle_timeout
        while True:
            now = self._monotonic()
            remaining = deadline - now
            if remaining <= 0:
                if self._try_retire():
                    return _SHUTDOWNREQUEST
                # The pool is at its minimum (or work is queued): stay
                # alive and restart the idle countdown.
                deadline = now + self.idle_timeout
                remaining = self.idle_timeout
            if self._idle_poll_interval is not None:
                remaining = min(remaining, self._idle_poll_interval)
            try:
                return self._queue.get(timeout=remaining)
            except queue.Empty:
                continue

    def put(self, obj):
        """Put request into queue.

        Args:
            obj (:py:class:`~cheroot.server.HTTPConnection`): HTTP connection
                waiting to be processed
        """
        self._queue.put(obj, block=True, timeout=self._queue_put_timeout)
        if self.idle_timeout is not None:
            self._grow_for_backlog()

    def _grow_for_backlog(self):
        """Spawn extra workers if queued connections outnumber idle ones."""
        backlog = self._queue.qsize() - self.idle
        if backlog > 0:
            self.grow(backlog)

    def _try_retire(self):
        """Try to reserve a retirement slot for the calling worker.

        The decision is serialized with every other grow/shrink decision,
        so a herd of simultaneously idle workers cannot all conclude they
        may exit: only workers above the ``min`` floor retire, one
        decision at a time. A queued connection arriving concurrently
        with the decision cannot be lost either—retirement is refused
        while the queue holds work, and at least ``min`` workers always
        remain blocked in :meth:`get` to pick up anything enqueued just
        after the check.

        Returns True when the caller must terminate itself.
        """
        with self._membership_lock:
            self._clear_dead_threads()
            spare = len(self._threads) - len(self._pending_shutdowns)
            if spare <= self.min or not self._queue.empty():
                return False
            # Account for the caller exactly like a manually shrunk
            # worker: _clear_dead_threads() will drop the marker once
            # the thread is gone.
            self._pending_shutdowns.append(None)
            return True

    def _clear_dead_threads(self):
        # Callers must hold _membership_lock.
        # Remove any dead threads from our list
        for t in [t for t in self._threads if not t.is_alive()]:
            self._threads.remove(t)
            with contextlib.suppress(IndexError):
                self._pending_shutdowns.popleft()

    def grow(self, amount):
        """Spawn new worker threads (not above self.max)."""
        with self._membership_lock:
            self._clear_dead_threads()
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
        with self._membership_lock:
            # Remove any dead threads from our list
            amount -= len(self._pending_shutdowns)
            self._clear_dead_threads()
            if amount <= 0:
                return

            # calculate the number of threads above the minimum
            n_extra = max(len(self._threads) - self.min, 0)

            # don't remove more than amount
            n_to_remove = min(amount, n_extra)

            # put shutdown requests on the queue equal to the number of
            # threads to remove. As each request is processed by a worker,
            # that worker will terminate and be culled from the list.
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
            endtime = self._monotonic() + timeout

        # Must shut down threads here so the code that calls
        # this method can know when all threads are stopped.
        # Idle workers blocked in get() are woken up immediately by
        # these sentinels; stopping never waits for the idle timeout
        # to expire first.
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
            remaining_time = timeout and endtime - self._monotonic()
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
