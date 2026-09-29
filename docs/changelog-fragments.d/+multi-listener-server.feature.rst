Added :py:class:`cheroot.server.MultiListenerHTTPServer`, a two-phase
(prepare/start) multi-listener entry point: it binds a set of addresses
with all-or-nothing semantics, rolling back already-bound listeners if
any of them fails, supports adopting externally supplied sockets with
explicit ownership, and can be prepared again after being stopped.
