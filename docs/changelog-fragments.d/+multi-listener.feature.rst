Added :py:class:`~cheroot.server.Listener` and
:py:class:`~cheroot.server.MultiListenerServer`, a multi-listener
entry point with a two-phase ``prepare()``/``start()`` lifecycle.

The prepare phase resolves addresses, configures sockets and
validates TLS adapters for all listeners atomically: when binding one
address fails, the already prepared listeners are rolled back instead
of being left behind as half-started services. Externally supplied
sockets require an explicit ownership declaration and only owned
sockets are closed on shutdown. A stopped server may be prepared and
started again.
