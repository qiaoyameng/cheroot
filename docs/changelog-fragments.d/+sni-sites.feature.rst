Added SNI-based TLS virtual hosting: ``cheroot.ssl.Adapter.add_sni_site()``
registers per-site certificates, keys and client certificate requirements on
a single listening socket. Sites are selected during the TLS handshake by
exact hostname or single-label wildcards (``*.example.com``), with
case-folding, IDNA normalization and duplicate detection applied at
registration time. The new ``sni_missing`` and ``sni_unknown`` adapter
attributes control whether clients that send no SNI or an unconfigured
hostname fall back to the default site or are rejected. This is implemented
by ``BuiltinSSLAdapter``; the pyOpenSSL adapter raises
``NotImplementedError`` for now.
