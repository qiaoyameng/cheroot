"""Implementation of the SSL adapter base interface."""

import re as _re
import socket as _socket
from abc import ABC, abstractmethod
from getpass import getpass as _ask_for_password_interactively
from types import MappingProxyType as _MappingProxyType
from warnings import warn as _warn

from .. import errors as _errors


_SNI_HOSTNAME_LABEL_RE = _re.compile(
    r'\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z',
)


SNI_FALLBACK_DEFAULT = 'default'
"""Policy value: serve the connection with the default TLS context."""

SNI_FALLBACK_REJECT = 'reject'
"""Policy value: refuse the connection."""

_SNI_FALLBACK_POLICIES = frozenset(
    {
        SNI_FALLBACK_DEFAULT,
        SNI_FALLBACK_REJECT,
    },
)


def _normalize_sni_hostname(hostname, /):
    """Return a canonical form of an SNI hostname for matching.

    The hostname is lowercased, any trailing dot is stripped and
    internationalized labels are converted to their IDNA A-label
    (``xn--`` prefixed) form. Wildcard prefixes (``*.``) are preserved.

    :raises ValueError: if the hostname is empty or not IDNA-encodable
    """
    if not isinstance(hostname, str):
        raise ValueError(
            'SNI hostnames must be text, got %r' % (hostname,),
        )

    normalized = hostname.strip().rstrip('.')
    if not normalized:
        raise ValueError('SNI hostnames must not be empty')

    try:
        normalized = normalized.encode('idna').decode('ascii')
    except UnicodeError as unicode_error:
        raise ValueError(
            'SNI hostname %r cannot be IDNA-encoded' % (hostname,),
        ) from unicode_error

    labels = normalized.lower().split('.')
    if labels[0] == '*':
        labels = labels[1:]
    if not labels or any(
        _SNI_HOSTNAME_LABEL_RE.match(label) is None for label in labels
    ):
        raise ValueError(
            'SNI hostname %r contains invalid DNS labels' % (hostname,),
        )

    return normalized.lower()


class SniSiteConfig:
    """TLS configuration of a single SNI-selected site."""

    def __init__(
        self,
        hostname,
        certificate,
        private_key,
        certificate_chain=None,
        ciphers=None,
        *,
        private_key_password=None,
        verify_mode=None,
    ):
        """Store per-site TLS settings; the context is built separately."""
        self.hostname = hostname
        self.certificate = certificate
        self.private_key = private_key
        self.certificate_chain = certificate_chain
        self.ciphers = ciphers
        self.private_key_password = private_key_password
        self.verify_mode = verify_mode
        self.context = None

    def __repr__(self):
        """Render a debug representation of the site config."""
        return '%s(hostname=%r)' % (type(self).__name__, self.hostname)


def _ensure_peer_speaks_https(raw_socket, /) -> None:
    """
    Raise exception if the client sent plain HTTP.

    This method probes the TCP stream for signs of the peer having
    sent us plaintext HTTP on the HTTPS port by peeking at the
    first bytes. If there's no data yet, the method considers the
    guess inconclusive and does not error out. This allows the server
    to continue until the SSL handshake is attempted, at which point
    an error will be caught by the SSL layer if the client
    is not speaking TLS.

    :raises NoSSLError: When plaintext HTTP is detected on an HTTPS socket
    """
    PEEK_BYTES = 16
    PEEK_TIMEOUT = 0.5

    original_timeout = raw_socket.gettimeout()
    raw_socket.settimeout(PEEK_TIMEOUT)

    try:
        first_bytes = raw_socket.recv(PEEK_BYTES, _socket.MSG_PEEK)
    except (OSError, _socket.timeout):
        return
    finally:
        raw_socket.settimeout(original_timeout)

    if not first_bytes:
        return

    http_methods = (
        b'GET ',
        b'POST ',
        b'PUT ',
        b'DELETE ',
        b'HEAD ',
        b'OPTIONS ',
        b'PATCH ',
        b'CONNECT ',
        b'TRACE ',
    )
    if first_bytes.startswith(http_methods):
        raise _errors.NoSSLError(
            'Expected HTTPS on the socket but got plain HTTP',
        ) from None


class Adapter(ABC):
    """Base class for SSL driver library adapters.

    Required methods:

        * ``wrap(sock) -> (wrapped socket, ssl environ dict)``
        * ``makefile(sock, mode='r', bufsize=DEFAULT_BUFFER_SIZE) ->
          socket file object``
    """

    @abstractmethod
    def __init__(
        self,
        certificate,
        private_key,
        certificate_chain=None,
        ciphers=None,
        *,
        private_key_password=None,
    ):
        """Set up certificates, private key, ciphers and reset context."""
        self.certificate = certificate
        self.private_key = private_key
        self.certificate_chain = certificate_chain
        self.ciphers = ciphers
        self.private_key_password = private_key_password
        self._sni_sites = {}
        self._sni_missing = SNI_FALLBACK_DEFAULT
        self._sni_unknown = SNI_FALLBACK_DEFAULT
        self.context = None

    @property
    def sni_sites(self):
        """Read-only mapping of normalized hostnames to SNI site configs."""
        return _MappingProxyType(self._sni_sites)

    @property
    def sni_missing(self):
        """Policy for clients that do not send SNI.

        Either ``'default'`` (serve with the default TLS context)
        or ``'reject'`` (refuse the connection).
        """
        return self._sni_missing

    @sni_missing.setter
    def sni_missing(self, policy):
        """Validate and set the no-SNI fallback policy."""
        self._sni_missing = self._validate_sni_fallback_policy(policy)

    @property
    def sni_unknown(self):
        """Policy for clients sending an SNI hostname with no configured site.

        Either ``'default'`` (serve with the default TLS context)
        or ``'reject'`` (refuse the connection).
        """
        return self._sni_unknown

    @sni_unknown.setter
    def sni_unknown(self, policy):
        """Validate and set the unknown-SNI fallback policy."""
        self._sni_unknown = self._validate_sni_fallback_policy(policy)

    @staticmethod
    def _validate_sni_fallback_policy(policy, /):
        """Check that the given fallback policy is a known one."""
        if policy not in _SNI_FALLBACK_POLICIES:
            raise ValueError(
                'SNI fallback policy must be one of %r, got %r'
                % (sorted(_SNI_FALLBACK_POLICIES), policy),
            )
        return policy

    def add_sni_site(
        self,
        hostname,
        certificate,
        private_key,
        certificate_chain=None,
        ciphers=None,
        *,
        private_key_password=None,
        verify_mode=None,
    ):
        """Register an SNI site to be served from this adapter's socket.

        ``hostname`` may be an exact hostname or a wildcard of the form
        ``*.example.com`` (matching exactly one DNS label). Hostnames are
        normalized (case-folded, IDNA-encoded) before being stored, so
        configuration mistakes like duplicates are reported eagerly.

        :raises ValueError: on invalid or duplicate hostnames
        """
        normalized_hostname = _normalize_sni_hostname(hostname)
        if normalized_hostname in self._sni_sites:
            raise ValueError(
                'Duplicate SNI site configured for %r'
                % (normalized_hostname,),
            )

        site = SniSiteConfig(
            normalized_hostname,
            certificate,
            private_key,
            certificate_chain,
            ciphers,
            private_key_password=private_key_password,
            verify_mode=verify_mode,
        )
        site.context = self._build_sni_context(site)
        self._sni_sites[normalized_hostname] = site
        self._sni_site_registered(site)
        return site

    def _sni_site_registered(self, site, /):
        """Hook invoked after an SNI site has been registered.

        Adapters may use it to adjust their default TLS context to
        accommodate the new site.
        """

    def _build_sni_context(self, site, /):
        """Build a TLS context for an SNI site.

        Adapters that support SNI-based virtual hosting must override
        this hook.

        :raises NotImplementedError: when the adapter has no SNI support
        """
        raise NotImplementedError(
            '%s does not support SNI site configuration'
            % (type(self).__name__,),
        )

    def _match_sni_site(self, server_name, /):
        """Look up the SNI site config for a client-requested hostname.

        Exact hostname matches take precedence over wildcard sites.
        Returns ``None`` when no site matches.
        """
        try:
            normalized = _normalize_sni_hostname(server_name)
        except ValueError:
            return None

        site = self._sni_sites.get(normalized)
        if site is not None:
            return site

        first_label, dot, parent_domain = normalized.partition('.')
        if not first_label or not dot:
            return None
        return self._sni_sites.get('*.%s' % (parent_domain,))

    def bind(self, sock):
        """
        Return the given socket.

        Deprecated:
        This method no longer performs any SSL-specific operations.
        SSL wrapping now happens in :meth:`.wrap`. :meth:`.bind` will be
        removed in a future version.
        """
        _warn(
            'SSLAdapter.bind() is deprecated and will be removed in a future version.',
            DeprecationWarning,
            stacklevel=2,
        )
        return sock

    @abstractmethod
    def wrap(self, sock):
        """Wrap the given socket and return WSGI environ entries."""
        _ensure_peer_speaks_https(sock)
        return sock, {}

    @abstractmethod
    def get_environ(self):
        """Return WSGI environ entries to be merged into each request."""
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def makefile(self, sock, mode='r', bufsize=-1):
        """Return socket file object."""
        raise NotImplementedError  # pragma: no cover

    def _prompt_for_tls_password(self) -> str:
        """Prompt for encrypted private key password interactively."""
        prompt = 'Enter PEM pass phrase: '
        return _ask_for_password_interactively(prompt)
