"""Implementation of the SSL adapter base interface."""

import socket as _socket
from abc import ABC, abstractmethod
from getpass import getpass as _ask_for_password_interactively
from warnings import warn as _warn

from .. import errors as _errors


_CLIENT_VERIFY_MODES = frozenset(('none', 'optional', 'required'))

_SNI_POLICIES = frozenset(('default', 'reject'))


class SNIRejected(Exception):
    """Raised when an SNI host name must be rejected per policy."""


def _normalize_hostname(hostname, /):
    """Normalize a DNS host name for SNI matching.

    Folds case, strips a single trailing dot and converts
    internationalized labels to their IDNA A-label form so that
    visually identical names configured differently compare equal.
    Wildcard names must use a single left-most ``*.`` label.
    """
    if not isinstance(hostname, str):
        raise TypeError(
            'Expected a host name string, got '
            f'{type(hostname).__name__}.',
        )
    name = hostname.strip().rstrip('.')
    wildcard = name.startswith('*.')
    if wildcard:
        name = name[2:]
    if not name:
        raise ValueError(f'Host names must not be empty: {hostname!r}.')
    if '*' in name:
        raise ValueError(
            'Wildcards are only supported as a single left-most '
            f'label: {hostname!r}.',
        )
    try:
        name = name.encode('idna').decode('ascii')
    except UnicodeError as unicode_error:
        raise ValueError(
            f'Invalid internationalized host name: {hostname!r}.',
        ) from unicode_error
    name = name.lower()
    return f'*.{name}' if wildcard else name


class SNISite:
    """TLS configuration of a single SNI-selected site.

    :param certificate: the file name of the site's TLS certificate
    :param private_key: the file name of the site's private key file
    :param certificate_chain: optional file name of the certificate
        chain file; it is also used as the trust store for verifying
        client certificates when ``client_verify_mode`` requests them
    :param ciphers: optional ciphers list for this site
    :param private_key_password: optional passphrase (or a callable
        returning one) for a password protected private key
    :param client_verify_mode: client certificate requirement for
        this site -- one of ``'none'`` (default), ``'optional'`` or
        ``'required'``
    """

    def __init__(
        self,
        certificate,
        private_key,
        certificate_chain=None,
        ciphers=None,
        *,
        private_key_password=None,
        client_verify_mode='none',
    ):
        """Set up the per-site TLS configuration."""
        self.certificate = certificate
        self.private_key = private_key
        self.certificate_chain = certificate_chain
        self.ciphers = ciphers
        self.private_key_password = private_key_password
        self.client_verify_mode = self._validate_client_verify_mode(
            client_verify_mode,
        )

    @staticmethod
    def _validate_client_verify_mode(client_verify_mode):
        try:
            normalized = client_verify_mode.lower()
        except AttributeError:
            raise TypeError(
                'client_verify_mode must be one of '
                f'{sorted(_CLIENT_VERIFY_MODES)}, got '
                f'{client_verify_mode!r}.',
            ) from None
        if normalized not in _CLIENT_VERIFY_MODES:
            raise ValueError(
                'client_verify_mode must be one of '
                f'{sorted(_CLIENT_VERIFY_MODES)}, got '
                f'{client_verify_mode!r}.',
            )
        return normalized

    def __repr__(self):
        """Render a short representation of the site."""
        return (
            f'{self.__class__.__name__}('
            f'certificate={self.certificate!r}, '
            f'client_verify_mode={self.client_verify_mode!r})'
        )


class SNIMap:
    """A mapping of host names to per-site TLS configurations.

    Host names are normalized (case folding, IDNA, trailing dots)
    when the map is constructed; duplicates that normalize to the
    same name are rejected eagerly.

    :param sites: a mapping of host names to :class:`SNISite`
        instances; names may use a single left-most ``*.`` wildcard
        label which matches exactly one DNS label
    :param missing_sni: what to do when the client does not send an
        SNI host name -- ``'default'`` (use the adapter's own
        certificate) or ``'reject'`` (abort the handshake)
    :param unknown_sni: what to do when the client-sent SNI host
        name matches no configured site -- ``'default'`` or
        ``'reject'``, as above

    .. note::

       OpenSSL keeps the client-certificate verification flags of
       the *initial* TLS context when the context is switched via
       SNI. The adapters therefore upgrade the default context to
       request (but not require) client certificates when any
       configured site uses a ``client_verify_mode`` other than
       ``'none'``, and enforce per-site ``'required'`` policies
       after the handshake. Client certificates are always verified
       against the trust store (``certificate_chain``) of the site
       whose context was selected.
    """

    def __init__(self, sites, *, missing_sni='default', unknown_sni='default'):
        """Normalize and validate the site configuration."""
        self.missing_sni = self._validate_policy('missing_sni', missing_sni)
        self.unknown_sni = self._validate_policy('unknown_sni', unknown_sni)
        self._sites = {}
        for hostname, site in dict(sites).items():
            normalized = _normalize_hostname(hostname)
            if normalized in self._sites:
                raise ValueError(
                    'Duplicate SNI site configuration for '
                    f'{normalized!r}.',
                )
            if not isinstance(site, SNISite):
                raise TypeError(
                    f'SNI site for {hostname!r} must be an SNISite '
                    f'instance, got {type(site).__name__}.',
                )
            self._sites[normalized] = site

    @staticmethod
    def _validate_policy(name, policy):
        try:
            normalized = policy.lower()
        except AttributeError:
            raise TypeError(
                f'{name} must be one of {sorted(_SNI_POLICIES)}, '
                f'got {policy!r}.',
            ) from None
        if normalized not in _SNI_POLICIES:
            raise ValueError(
                f'{name} must be one of {sorted(_SNI_POLICIES)}, '
                f'got {policy!r}.',
            )
        return normalized

    def __len__(self):
        """Return the number of configured sites."""
        return len(self._sites)

    def __contains__(self, hostname):
        """Check whether a normalized host name is configured."""
        return hostname in self._sites

    def items(self):
        """Iterate over ``(normalized host name, SNISite)`` pairs."""
        return self._sites.items()

    def resolve(self, server_name):
        """Return the site key to use for a client-sent SNI name.

        Returns the normalized host name of the matching site, or
        :data:`None` when the connection should continue with the
        default (adapter-level) TLS context.

        Exact matches win over wildcard matches; a wildcard
        ``*.example.com`` matches exactly one label, i.e.
        ``www.example.com`` but neither ``example.com`` nor
        ``a.b.example.com``.

        :raises SNIRejected: when the applicable policy is ``'reject'``
        """
        if not server_name:
            if self.missing_sni == 'reject':
                raise SNIRejected(
                    'The client did not send an SNI host name.',
                )
            return None
        try:
            normalized = _normalize_hostname(server_name)
        except (TypeError, ValueError):
            normalized = None
        if normalized is not None:
            if normalized in self._sites:
                return normalized
            _first_label, _dot, parent = normalized.partition('.')
            if _first_label and _dot:
                wildcard_key = f'*.{parent}'
                if wildcard_key in self._sites:
                    return wildcard_key
        if self.unknown_sni == 'reject':
            raise SNIRejected(
                f'No SNI site configured for {server_name!r}.',
            )
        return None

    def site_for(self, server_name):
        """Return the :class:`SNISite` for a client-sent SNI name.

        Like :meth:`resolve`, but returns the site itself (or
        :data:`None` when the default site applies).

        :raises SNIRejected: when the applicable policy is ``'reject'``
        """
        site_key = self.resolve(server_name)
        if site_key is None:
            return None
        return self._sites[site_key]


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
        sni=None,
    ):
        """Set up certificates, private key, ciphers and reset context.

        :param sni: optional SNI virtual hosting configuration --
            an :class:`SNIMap` instance, or a mapping of host names
            to :class:`SNISite` instances (which is converted to an
            :class:`SNIMap` with default policies)
        """
        self.certificate = certificate
        self.private_key = private_key
        self.certificate_chain = certificate_chain
        self.ciphers = ciphers
        self.private_key_password = private_key_password
        if sni is not None and not isinstance(sni, SNIMap):
            sni = SNIMap(sni)
        self.sni = sni
        self.context = None

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
