Added :py:class:`~cheroot.workers.threadpool.SharedExecutionQuota`
allowing several server endpoints (for example, data and management
listeners) to share worker capacity: each endpoint gets guaranteed
reserved execution slots plus access to a common pool of shared
slots, so management requests keep being served even when the data
endpoint is saturated.
