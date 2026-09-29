"""Tests for the idle-timeout auto-scaling of the worker thread pool."""

import threading
import time
import types

import pytest

from ..workers.threadpool import ThreadPool


MIN_THREADS = 2
MAX_THREADS = 6
IDLE_TIMEOUT = 30.0


class FakeClock:
    """A manually advanced stand-in for :py:func:`time.monotonic`."""

    def __init__(self):
        """Initialize the clock at zero."""
        self.now = 0.0

    def __call__(self):
        """Return the current fake time."""
        return self.now

    def advance(self, seconds):
        """Move the clock forward."""
        self.now += seconds


class BlockingConn:
    """A fake connection occupying its worker until released."""

    def __init__(self, release):
        """Initialize the fake connection."""
        self._release = release
        self.started = threading.Event()
        self.closed = False

    def communicate(self):
        """Block until the test releases all connections."""
        self.started.set()
        self._release.wait(timeout=5)
        return False

    def close(self):
        """Mark the connection as closed."""
        self.closed = True


class InstantConn:
    """A fake connection that is processed immediately."""

    def __init__(self):
        """Initialize the fake connection."""
        self.processed = threading.Event()

    def communicate(self):
        """Record that the connection was processed."""
        self.processed.set()
        return False

    def close(self):
        """Pretend to close the connection."""


def make_pool(clock):
    """Create a pool wired to a fake server and the fake clock."""
    pool = ThreadPool(
        server=None,
        min=MIN_THREADS,
        max=MAX_THREADS,
        idle_timeout=IDLE_TIMEOUT,
    )
    pool.server = types.SimpleNamespace(
        requests=pool,
        stats={'Enabled': False, 'Worker Threads': {}},
        error_log=lambda *args, **kwargs: None,
    )
    pool._monotonic = clock  # noqa: SLF001
    # Let the workers observe fake-clock jumps within milliseconds of
    # real time instead of sleeping through the whole idle budget.
    pool._idle_poll_interval = 0.01  # noqa: SLF001
    return pool


def alive_threads(pool):
    """Return the number of pool threads that are still running."""
    return sum(worker.is_alive() for worker in pool._threads)  # noqa: SLF001


def wait_for(predicate, timeout=5.0):
    """Poll the predicate until it holds or the real timeout expires."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.005)
    return False


def test_idle_timeout_must_not_be_negative():
    """The pool rejects a negative idle timeout."""
    with pytest.raises(ValueError, match='idle_timeout=-1 must be >= 0'):
        ThreadPool(server=None, idle_timeout=-1)


def test_manual_grow_and_shrink_respect_bounds():
    """Manual grow/shrink stay within the min/max bounds."""
    pool = make_pool(FakeClock())
    pool.start()
    try:
        pool.grow(100)  # capped by max
        assert wait_for(lambda: alive_threads(pool) == MAX_THREADS)

        pool.shrink(100)  # floored by min
        assert wait_for(lambda: alive_threads(pool) == MIN_THREADS)
    finally:
        pool.stop(timeout=1)


def test_idle_scaling_through_traffic_phases(capsys):
    """Show pool size across burst, brief pause and long idle phases.

    Uses a fake monotonic clock: a burst of traffic grows the pool up to
    ``max``, a pause shorter than the idle timeout changes nothing, and
    a long idle stretch retires the extra workers back down to ``min``.
    """
    clock = FakeClock()
    pool = make_pool(clock)
    pool.start()
    timeline = [('pool start', alive_threads(pool))]

    try:
        # Phase 1: a burst of connections grows the pool up to max.
        release = threading.Event()
        conns = [BlockingConn(release) for _ in range(MAX_THREADS)]
        for conn in conns:
            pool.put(conn)
        assert wait_for(lambda: alive_threads(pool) == MAX_THREADS)
        assert wait_for(lambda: all(c.started.is_set() for c in conns))
        timeline.append(('burst traffic', alive_threads(pool)))

        # No connection may be lost, however scaling decisions interleave.
        release.set()
        assert wait_for(lambda: all(c.closed for c in conns))

        # Phase 2: a pause shorter than the idle timeout keeps workers.
        clock.advance(IDLE_TIMEOUT / 3)
        time.sleep(0.2)  # give workers a few fake-clock observations
        timeline.append(('brief pause', alive_threads(pool)))

        # Phase 3: a long idle stretch retires workers down to min.
        clock.advance(IDLE_TIMEOUT * 2)
        assert wait_for(lambda: alive_threads(pool) == MIN_THREADS)
        timeline.append(('long idle', alive_threads(pool)))
    finally:
        pool.stop(timeout=1)

    with capsys.disabled():
        print('\nworker threads by phase (fake clock):')
        for phase, count in timeline:
            print(f'  {phase:<15} {count}')

    assert [count for _phase, count in timeline] == [
        MIN_THREADS,
        MAX_THREADS,
        MAX_THREADS,
        MIN_THREADS,
    ]


def test_no_connection_lost_while_workers_retire():
    """Connections enqueued as workers decide to retire are processed."""
    clock = FakeClock()
    pool = make_pool(clock)
    pool.start()
    try:
        pool.grow(MAX_THREADS - MIN_THREADS)
        assert wait_for(lambda: alive_threads(pool) == MAX_THREADS)

        conns = [InstantConn() for _ in range(50)]
        for conn in conns:
            # Let idle workers hit their retirement deadline at the same
            # moment new work shows up in the queue.
            clock.advance(IDLE_TIMEOUT * 2)
            pool.put(conn)

        assert wait_for(lambda: all(c.processed.is_set() for c in conns))
        assert alive_threads(pool) >= MIN_THREADS
    finally:
        pool.stop(timeout=1)
