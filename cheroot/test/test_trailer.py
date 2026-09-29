"""Tests for the read-only chunked-request trailer extension."""

import http.client
import json
import socket

import pytest

from cheroot import wsgi
from cheroot._compat import IS_MACOS, IS_WINDOWS


IS_SLOW_ENV = IS_MACOS or IS_WINDOWS


def trailer_app(environ, start_response):
    """WSGI app reporting the request body and its trailers as JSON."""
    path = environ['PATH_INFO']
    get_trailers = environ.get('cheroot.trailers')
    get_mismatch = environ.get('cheroot.trailer_mismatch')

    result = {
        'has_trailers_callable': get_trailers is not None,
        'premature_error': None,
        'body': None,
        'trailers': None,
        'mismatch': None,
        'http_x_checksum': environ.get('HTTP_X_CHECKSUM'),
        'http_host': environ.get('HTTP_HOST'),
        'http_authorization': environ.get('HTTP_AUTHORIZATION'),
        'content_length': environ.get('CONTENT_LENGTH'),
    }

    if path == '/early':
        # Respond without ever touching the request body.
        pass
    else:
        if path == '/premature':
            try:
                get_trailers()
            except ValueError as ex:
                result['premature_error'] = str(ex)
        result['body'] = environ['wsgi.input'].read().decode('utf-8')
        if get_trailers is not None:
            result['trailers'] = get_trailers()
            result['mismatch'] = get_mismatch()

    payload = json.dumps(result).encode('utf-8')
    start_response(
        '200 OK',
        [
            ('Content-Type', 'application/json'),
            ('Content-Length', str(len(payload))),
        ],
    )
    return [payload]


@pytest.fixture
def trailer_server():
    """Run a WSGI server exposing the trailer test app."""
    server = wsgi.Server(
        ('127.0.0.1', 0),
        trailer_app,
        timeout=600 if IS_SLOW_ENV else 20,
    )
    with server._run_in_thread():
        yield server


def _encode_chunked(chunks, trailers=()):
    """Serialize ``chunks`` and ``trailers`` into chunked transfer coding."""
    wire = b''.join(
        b'%x\r\n%s\r\n' % (len(chunk), chunk)
        for chunk in chunks
    )
    wire += b'0\r\n'
    wire += b''.join(
        name + b': ' + value + b'\r\n'
        for name, value in trailers
    )
    return wire + b'\r\n'


def _fragment(data, size):
    """Split ``data`` into fragments of at most ``size`` bytes."""
    if size is None:
        return [data]
    return [data[pos:pos + size] for pos in range(0, len(data), size)]


def _request(
    server,
    path='/',
    chunks=(b'hello', b' ', b'world'),
    trailers=(),
    headers=(),
    fragment_size=None,
    http_conn=None,
):
    """Send a chunked POST, fragmented arbitrarily, and return the JSON."""
    own_conn = http_conn is None
    conn = http_conn or http.client.HTTPConnection(
        *server.bind_addr,
        timeout=10,
    )
    conn.putrequest('POST', path, skip_host=True)
    conn.putheader('Host', conn.host)
    conn.putheader('Transfer-Encoding', 'chunked')
    for name, value in headers:
        conn.putheader(name, value)
    conn.endheaders()
    wire = _encode_chunked(chunks, trailers)
    for piece in _fragment(wire, fragment_size):
        conn.send(piece)
    response = conn.getresponse()
    raw = response.read()
    try:
        parsed = json.loads(raw.decode('utf-8'))
    except ValueError:
        parsed = None
    if own_conn:
        conn.close()
    return response, parsed


FRAGMENT_SIZES = (1, 2, 3, 5, 7, 16, 64, None)


@pytest.mark.parametrize('fragment_size', FRAGMENT_SIZES)
def test_trailers_available_after_full_read(trailer_server, fragment_size):
    """Trailers parse identically under arbitrary chunk boundaries."""
    response, result = _request(
        trailer_server,
        chunks=(b'chunk-one', b'chunk-two', b'!' * 17),
        trailers=(
            (b'X-Checksum', b'deadbeef'),
            (b'X-Signature', b'cafe'),
        ),
        headers=(('Trailer', 'X-Checksum, X-Signature'),),
        fragment_size=fragment_size,
    )
    assert response.status == 200
    assert result['body'] == 'chunk-one' + 'chunk-two' + '!' * 17
    assert result['trailers'] == {
        'X-Checksum': 'deadbeef',
        'X-Signature': 'cafe',
    }
    assert result['mismatch'] == {'missing': [], 'undeclared': []}


@pytest.mark.parametrize('fragment_size', FRAGMENT_SIZES)
def test_empty_trailer_section(trailer_server, fragment_size):
    """A terminating chunk without trailers yields an empty mapping."""
    response, result = _request(
        trailer_server,
        fragment_size=fragment_size,
    )
    assert response.status == 200
    assert result['trailers'] == {}
    assert result['mismatch'] == {'missing': [], 'undeclared': []}


def test_trailers_unavailable_before_body_consumed(trailer_server):
    """Reading trailers before consuming the body must fail."""
    response, result = _request(
        trailer_server,
        path='/premature',
        trailers=((b'X-Checksum', b'deadbeef'),),
    )
    assert response.status == 200
    assert result['premature_error'] == (
        'Cannot read trailers until the request body has been read.'
    )
    # After the body has been consumed the trailers become available.
    assert result['trailers'] == {'X-Checksum': 'deadbeef'}


def test_forbidden_trailer_fields_are_dropped(trailer_server):
    """Framing, routing, and auth trailer fields must not be honored."""
    response, result = _request(
        trailer_server,
        trailers=(
            (b'Content-Length', b'3'),
            (b'Transfer-Encoding', b'identity'),
            (b'Host', b'evil.example.org'),
            (b'Authorization', b'Basic ZWxhc2NhcnQ='),
            (b'X-Checksum', b'deadbeef'),
        ),
    )
    assert response.status == 200
    assert result['trailers'] == {'X-Checksum': 'deadbeef'}
    # The forbidden fields did not leak into the request headers either.
    assert result['content_length'] is None
    assert result['http_authorization'] is None
    assert result['http_host'] != 'evil.example.org'


def test_duplicate_trailer_fields_follow_header_rules(trailer_server):
    """Repeated trailer fields fold like their regular header versions."""
    response, result = _request(
        trailer_server,
        trailers=(
            (b'Warning', b'199 Miscellaneous warning'),
            (b'Warning', b'199 Another warning'),
            (b'X-Checksum', b'first'),
            (b'X-Checksum', b'second'),
        ),
    )
    assert response.status == 200
    assert result['trailers'] == {
        # Comma-separated by rule:
        'Warning': '199 Miscellaneous warning, 199 Another warning',
        # Last one wins otherwise:
        'X-Checksum': 'second',
    }


def test_request_header_does_not_override_trailer(trailer_server):
    """A same-named request header and trailer stay independent."""
    response, result = _request(
        trailer_server,
        headers=(
            ('X-Checksum', 'header-value'),
            ('Trailer', 'X-Checksum'),
        ),
        trailers=((b'X-Checksum', b'trailer-value'),),
    )
    assert response.status == 200
    assert result['http_x_checksum'] == 'header-value'
    assert result['trailers'] == {'X-Checksum': 'trailer-value'}


def test_trailer_declaration_mismatch_reported(trailer_server):
    """Declaration mismatches are reported via a dedicated callable."""
    response, result = _request(
        trailer_server,
        headers=(('Trailer', 'X-Checksum, X-Missing'),),
        trailers=(
            (b'X-Checksum', b'deadbeef'),
            (b'X-Extra', b'surprise'),
        ),
    )
    assert response.status == 200
    assert result['trailers'] == {
        'X-Checksum': 'deadbeef',
        'X-Extra': 'surprise',
    }
    assert result['mismatch'] == {
        'missing': ['X-Missing'],
        'undeclared': ['X-Extra'],
    }


def test_trailers_callable_absent_without_chunked(trailer_server):
    """Non-chunked requests do not get the trailer extension."""
    conn = http.client.HTTPConnection(*trailer_server.bind_addr, timeout=10)
    conn.request(
        'POST',
        '/',
        body=b'abc',
        headers={'Content-Length': '3'},
    )
    response = conn.getresponse()
    result = json.loads(response.read().decode('utf-8'))
    conn.close()
    assert response.status == 200
    assert result['has_trailers_callable'] is False
    assert result['trailers'] is None


def test_early_response_drains_body_and_reuses_connection(trailer_server):
    """The server consumes the leftover body of early-finishing apps."""
    conn = http.client.HTTPConnection(*trailer_server.bind_addr, timeout=10)
    response, result = _request(
        trailer_server,
        path='/early',
        chunks=(b'unread ', b'body ', b'parts'),
        trailers=((b'X-Checksum', b'deadbeef'),),
        fragment_size=3,
        http_conn=conn,
    )
    assert response.status == 200
    assert result['body'] is None
    assert 'close' not in response.getheader('Connection', '')

    # The connection stays usable for the next request.
    response, result = _request(
        trailer_server,
        trailers=((b'X-Checksum', b'cafe'),),
        http_conn=conn,
    )
    assert response.status == 200
    assert result['body'] == 'hello world'
    assert result['trailers'] == {'X-Checksum': 'cafe'}
    conn.close()


def test_invalid_trailer_prevents_connection_reuse(trailer_server):
    """A malformed trailer section must take the connection down."""
    conn = http.client.HTTPConnection(*trailer_server.bind_addr, timeout=10)
    conn.putrequest('POST', '/early', skip_host=True)
    conn.putheader('Host', conn.host)
    conn.putheader('Transfer-Encoding', 'chunked')
    conn.endheaders()
    # The trailer line lacks a colon and is therefore illegal.
    conn.send(b'5\r\nhello\r\n0\r\nnot-a-header\r\n\r\n')
    response = conn.getresponse()
    response.read()
    assert response.status == 200
    assert response.getheader('Connection') == 'close'

    # The server must have dropped the connection.
    with pytest.raises((http.client.HTTPException, OSError)):
        conn.request('GET', '/')
        conn.getresponse()
    conn.close()


def test_unterminated_trailer_section_prevents_reuse(trailer_server):
    """A truncated trailer section must take the connection down."""
    conn = http.client.HTTPConnection(*trailer_server.bind_addr, timeout=10)
    conn.putrequest('POST', '/early', skip_host=True)
    conn.putheader('Host', conn.host)
    conn.putheader('Transfer-Encoding', 'chunked')
    conn.endheaders()
    # Terminating chunk without the final CRLF; then the client goes away.
    conn.send(b'5\r\nhello\r\n0\r\nX-Checksum: deadbeef\r\n')
    conn.sock.shutdown(socket.SHUT_WR)
    response = conn.getresponse()
    response.read()
    assert response.status == 200
    assert response.getheader('Connection') == 'close'
    conn.close()
