Added SNI-based TLS virtual hosting to the SSL adapters -- a single
listener can now serve multiple host names with different
certificates and client-certificate policies. Pass
:class:`cheroot.ssl.SNISite` instances via an
:class:`cheroot.ssl.SNIMap` (or a plain mapping) as the new ``sni``
argument of the ``builtin`` and ``pyOpenSSL`` adapters. Host names
are matched exactly or via single-label ``*.`` wildcards after
case/IDNA normalization, duplicates are rejected at startup, and
missing or unknown SNI names can independently fall back to the
default site or be rejected.
