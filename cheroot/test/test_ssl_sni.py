"""Tests for SNI-based TLS virtual hosting."""

import concurrent.futures
import ssl

import pytest

import trustme

from cheroot import errors
from cheroot.ssl import Adapter, _normalize_sni_hostname
from cheroot.ssl.builtin import BuiltinSSLAdapter


DEFAULT_HOSTNAME = 'default.test'
SECURE_HOSTNAME = 'secure.test'
PLAIN_HOSTNAME = 'plain.test'
WILDCARD_HOSTNAME = '*.apps.test'
WILDCARD_MATCH_HOSTNAME = 'foo.apps.test'
IDNA_HOSTNAME = 'münchen.test'
IDNA_HOSTNAME_ALABEL = 'xn--mnchen-3ya.test'
UNKNOWN_HOSTNAME = 'unknown.test'
CLIENT_IDENTITY = 'client.test'

HANDSHAKE_PUMP_LIMIT = 300


def _write_pem(tmp_dir, name, blob):
    """Persist a trustme blob and return its path."""
    path = tmp_dir / name
    blob.write_to_path(path)
    return str(path)


@pytest.fixture(scope='module')
def tls_material(tmp_path_factory):
    """Provide a CA and per-site certificates for SNI tests."""
    tmp_dir = tmp_path_factory.mktemp('sni-tls')
    ca = trustme.CA()

    material = {
        'ca_cert': _write_pem(tmp_dir, 'ca.pem', ca.cert_pem),
    }
    for site_name, identities in (
        ('default', (DEFAULT_HOSTNAME,)),
        ('secure', (SECURE_HOSTNAME,)),
        ('plain', (PLAIN_HOSTNAME,)),
        ('wildcard', (WILDCARD_HOSTNAME,)),
        ('idna', (IDNA_HOSTNAME,)),
    ):
        cert = ca.issue_cert(*identities)
        material['%s_chain' % site_name] = _write_pem(
            tmp_dir,
            '%s-chain.pem' % site_name,
            cert.private_key_and_cert_chain_pem,
        )
        material['%s_key' % site_name] = _write_pem(
            tmp_dir,
            '%s-key.pem' % site_name,
            cert.private_key_pem,
        )
        material['%s_leaf_der' % site_name] = ssl.PEM_cert_to_DER_cert(
            cert.cert_chain_pems[0].bytes().decode('ascii'),
        )

    client_cert = ca.issue_cert(CLIENT_IDENTITY)
    material['client_chain'] = _write_pem(
        tmp_dir,
        'client-chain.pem',
        client_cert.private_key_and_cert_chain_pem,
    )
    other_client_cert = trustme.CA().issue_cert(CLIENT_IDENTITY)
    material['other_client_chain'] = _write_pem(
        tmp_dir,
        'other-client-chain.pem',
        other_client_cert.private_key_and_cert_chain_pem,
    )
    return material


@pytest.fixture
def sni_adapter(tls_material):
    """Provide a builtin adapter with several SNI sites configured."""
    adapter = BuiltinSSLAdapter(
        tls_material['default_chain'],
        tls_material['default_key'],
    )
    adapter.add_sni_site(
        SECURE_HOSTNAME,
        tls_material['secure_chain'],
        tls_material['secure_key'],
        certificate_chain=tls_material['ca_cert'],
        verify_mode=ssl.CERT_REQUIRED,
    )
    adapter.add_sni_site(
        PLAIN_HOSTNAME,
        tls_material['plain_chain'],
        tls_material['plain_key'],
    )
    adapter.add_sni_site(
        WILDCARD_HOSTNAME,
        tls_material['wildcard_chain'],
        tls_material['wildcard_key'],
    )
    adapter.add_sni_site(
        IDNA_HOSTNAME,
        tls_material['idna_chain'],
        tls_material['idna_key'],
    )
    return adapter


class _HandshakeResult:
    """Outcome of one in-process handshake through the adapter."""

    def __init__(self):
        self.server_obj = None
        self.server_environ = None
        self.server_error = None
        self.client_obj = None
        self.client_error = None


def _pump_bios(server_out, client_out, server_in, client_in):
    """Shuttle pending bytes between the client and server BIOs."""
    outgoing_client = client_out.read()
    if outgoing_client:
        server_in.write(outgoing_client)
    outgoing_server = server_out.read()
    if outgoing_server:
        client_in.write(outgoing_server)


def _run_handshake(adapter, server_hostname, *, client_cert_chain=None):
    """Run an in-process TLS handshake against the adapter.

    The server side mirrors what :meth:`BuiltinSSLAdapter.wrap` does
    for an accepted connection: it handshakes against the adapter's
    context (triggering the SNI dispatch), applies the post-handshake
    SNI policies and computes the WSGI environ. ``ssl.MemoryBIO`` is
    used so no actual sockets are needed.
    """
    result = _HandshakeResult()
    server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()

    server_obj = adapter.context.wrap_bio(
        server_in,
        server_out,
        server_side=True,
    )
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.check_hostname = False
    client_context.verify_mode = ssl.CERT_NONE
    if client_cert_chain is not None:
        client_context.load_cert_chain(client_cert_chain)
    client_obj = client_context.wrap_bio(
        client_in,
        client_out,
        server_side=False,
        server_hostname=server_hostname,
    )

    server_done = client_done = False
    for _ in range(HANDSHAKE_PUMP_LIMIT):
        if not client_done:
            try:
                client_obj.do_handshake()
                client_done = True
            except ssl.SSLWantReadError:
                pass
            except ssl.SSLError as tls_error:
                result.client_error = tls_error
                client_done = True
        _pump_bios(server_out, client_out, server_in, client_in)
        if not server_done:
            try:
                server_obj.do_handshake()
                server_done = True
            except ssl.SSLWantReadError:
                pass
            except ssl.SSLError as tls_error:
                result.server_error = tls_error
                server_done = True
        _pump_bios(server_out, client_out, server_in, client_in)
        if server_done and client_done:
            break

    assert server_done and client_done, 'handshake did not converge'
    result.server_obj = server_obj
    result.client_obj = client_obj
    if result.server_error is not None:
        return result

    # apply the same post-handshake policies as ``Adapter.wrap()``
    try:
        adapter._check_sni_missing(server_obj)
        adapter._check_sni_client_certificate(server_obj)
    except errors.FatalSSLAlert as tls_policy_error:
        result.server_error = tls_policy_error
        result.client_error = result.client_error or ConnectionError(
            'server dropped the connection',
        )
        return result

    result.server_environ = adapter.get_environ(server_obj)
    return result


@pytest.mark.parametrize(
    ('hostname', 'expected'),
    (
        ('example.com', 'example.com'),
        ('ExAmPlE.COM', 'example.com'),
        ('example.com.', 'example.com'),
        ('  example.com  ', 'example.com'),
        ('bücher.test', 'xn--bcher-kva.test'),
        ('BÜCHER.TEST', 'xn--bcher-kva.test'),
        ('*.Example.COM.', '*.example.com'),
        ('*.bücher.test', '*.xn--bcher-kva.test'),
    ),
)
def test_sni_hostname_normalization(hostname, expected):
    """Hostnames are case-folded, de-dotted and IDNA-encoded."""
    assert _normalize_sni_hostname(hostname) == expected


@pytest.mark.parametrize(
    'hostname',
    (
        '',
        '   ',
        '.',
        None,
        42,
        'not a hostname.test',
        'under_score.test',
        '-leading-hyphen.test',
    ),
)
def test_sni_hostname_normalization_rejects_invalid(hostname):
    """Empty, non-text and non-DNS hostnames are rejected."""
    with pytest.raises(ValueError, match='SNI hostname'):
        _normalize_sni_hostname(hostname)


@pytest.mark.parametrize(
    ('first', 'duplicate'),
    (
        ('example.test', 'EXAMPLE.test.'),
        ('bücher.test', 'xn--bcher-kva.test'),
        ('*.example.test', '*.EXAMPLE.test'),
    ),
)
def test_add_sni_site_rejects_duplicates(
    sni_adapter,
    tls_material,
    first,
    duplicate,
):
    """Duplicate sites are detected after normalization, at setup time."""
    sni_adapter.add_sni_site(
        first,
        tls_material['plain_chain'],
        tls_material['plain_key'],
    )
    with pytest.raises(ValueError, match='Duplicate SNI site'):
        sni_adapter.add_sni_site(
            duplicate,
            tls_material['plain_chain'],
            tls_material['plain_key'],
        )


@pytest.mark.parametrize('policy_attribute', ('sni_missing', 'sni_unknown'))
def test_sni_fallback_policy_validation(sni_adapter, policy_attribute):
    """Only 'default' and 'reject' are valid fallback policies."""
    assert getattr(sni_adapter, policy_attribute) == 'default'
    setattr(sni_adapter, policy_attribute, 'reject')
    assert getattr(sni_adapter, policy_attribute) == 'reject'
    with pytest.raises(ValueError, match='SNI fallback policy'):
        setattr(sni_adapter, policy_attribute, 'bogus')


def test_base_adapter_has_no_sni_context_builder(sni_adapter):
    """The base hook raises NotImplementedError (pyOpenSSL limitation)."""
    with pytest.raises(NotImplementedError, match='SNI'):
        Adapter._build_sni_context(sni_adapter, object())


def test_pyopenssl_adapter_rejects_sni_sites(tls_material):
    """The pyOpenSSL adapter documents its lack of SNI site support."""
    pytest.importorskip('OpenSSL')
    from cheroot.ssl.pyopenssl import pyOpenSSLAdapter

    adapter = pyOpenSSLAdapter(
        tls_material['default_chain'],
        tls_material['default_key'],
    )
    with pytest.raises(NotImplementedError, match='SNI'):
        adapter.add_sni_site(
            PLAIN_HOSTNAME,
            tls_material['plain_chain'],
            tls_material['plain_key'],
        )


@pytest.mark.parametrize(
    ('server_hostname', 'expected_site'),
    (
        (PLAIN_HOSTNAME, 'plain'),
        # hostname matching is case-insensitive
        ('PLAIN.TEST', 'plain'),
        # a trailing dot still matches
        ('plain.test.', 'plain'),
        # wildcard sites match exactly one label
        (WILDCARD_MATCH_HOSTNAME, 'wildcard'),
        # the wildcard base itself is not matched
        ('apps.test', 'default'),
        # wildcards do not match multiple labels
        ('a.b.apps.test', 'default'),
        # clients send IDNA A-labels for internationalized names
        (IDNA_HOSTNAME_ALABEL, 'idna'),
        # unknown names fall back to the default site
        (UNKNOWN_HOSTNAME, 'default'),
    ),
)
def test_sni_context_selection(
    sni_adapter,
    tls_material,
    server_hostname,
    expected_site,
):
    """The handshake selects contexts by exact and wildcard SNI names."""
    handshake = _run_handshake(sni_adapter, server_hostname)
    assert handshake.server_error is None
    assert handshake.client_error is None
    assert handshake.client_obj.getpeercert(binary_form=True) == (
        tls_material['%s_leaf_der' % expected_site]
    )
    assert handshake.server_environ['SSL_TLS_SNI'] == server_hostname


def test_sni_unknown_hostname_rejected(sni_adapter):
    """The 'reject' policy refuses handshakes with unknown SNI names."""
    sni_adapter.sni_unknown = 'reject'

    handshake = _run_handshake(sni_adapter, UNKNOWN_HOSTNAME)
    assert isinstance(handshake.client_error, ssl.SSLError)
    assert handshake.server_error is not None

    # known sites are still served
    handshake = _run_handshake(sni_adapter, PLAIN_HOSTNAME)
    assert handshake.server_error is None
    assert handshake.client_error is None


def test_sni_missing_hostname_rejected(sni_adapter):
    """The 'reject' policy refuses clients that do not send SNI."""
    sni_adapter.sni_missing = 'reject'

    handshake = _run_handshake(sni_adapter, None)
    assert isinstance(handshake.server_error, errors.FatalSSLAlert)
    assert handshake.client_error is not None

    # clients that do send SNI are unaffected
    handshake = _run_handshake(sni_adapter, PLAIN_HOSTNAME)
    assert handshake.server_error is None
    assert handshake.client_error is None


def test_sni_missing_hostname_default(sni_adapter, tls_material):
    """By default, clients without SNI are served by the default site."""
    handshake = _run_handshake(sni_adapter, None)
    assert handshake.server_error is None
    assert handshake.client_error is None
    assert handshake.client_obj.getpeercert(binary_form=True) == (
        tls_material['default_leaf_der']
    )
    assert handshake.server_environ.get('SSL_TLS_SNI') is None


def test_sni_client_certificate_required(sni_adapter, tls_material):
    """A site requiring client certs rejects clients without one."""
    handshake = _run_handshake(sni_adapter, SECURE_HOSTNAME)
    assert isinstance(handshake.server_error, errors.FatalSSLAlert)
    assert handshake.client_error is not None

    # a client certificate from a foreign CA is rejected in the handshake
    handshake = _run_handshake(
        sni_adapter,
        SECURE_HOSTNAME,
        client_cert_chain=tls_material['other_client_chain'],
    )
    assert handshake.server_error is not None

    handshake = _run_handshake(
        sni_adapter,
        SECURE_HOSTNAME,
        client_cert_chain=tls_material['client_chain'],
    )
    assert handshake.server_error is None
    assert handshake.client_error is None
    assert handshake.server_environ['SSL_CLIENT_VERIFY'] == 'SUCCESS'
    assert handshake.server_environ['SSL_TLS_SNI'] == SECURE_HOSTNAME


def test_sni_client_certificate_isolation_concurrent(
    sni_adapter,
    tls_material,
):
    """A client-cert site does not affect other sites on the same port.

    Handshakes against a site requiring client certificates and a site
    not requiring them are performed concurrently; each site must keep
    its own verification behavior.
    """
    handshakes_per_site = 10

    def connect(hostname, client_cert_chain=None):
        return hostname, _run_handshake(
            sni_adapter,
            hostname,
            client_cert_chain=client_cert_chain,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = []
        for _ in range(handshakes_per_site):
            futures.append(
                pool.submit(
                    connect,
                    SECURE_HOSTNAME,
                    tls_material['client_chain'],
                ),
            )
            futures.append(pool.submit(connect, PLAIN_HOSTNAME))
        results = [future.result(timeout=60) for future in futures]

    for hostname, handshake in results:
        assert handshake.server_error is None
        assert handshake.client_error is None
        expected_verify = (
            'SUCCESS' if hostname == SECURE_HOSTNAME else 'NONE'
        )
        assert handshake.server_environ['SSL_TLS_SNI'] == hostname
        assert handshake.server_environ['SSL_CLIENT_VERIFY'] == (
            expected_verify
        )
