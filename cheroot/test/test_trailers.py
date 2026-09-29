"""Tests for the read-only HTTP request trailer support."""

import io

import pytest

from cheroot import errors
from cheroot.server import (
    ChunkedRFile,
    HeaderReader,
    HTTPRequest,
    RequestTrailers,
)


def make_chunked_body(chunks, trailer_lines=()):
    """Build a chunked transfer-coded byte stream."""
    parts = [
        b''.join(
            (hex(len(chunk))[2:].encode('ascii'), b'\r\n', chunk, b'\r\n'),
        )
        for chunk in chunks
    ]
    parts.append(b'0\r\n')
    parts.extend(line + b'\r\n' for line in trailer_lines)
    parts.append(b'\r\n')
    return b''.join(parts)


def read_all(rfile):
    """Read a ChunkedRFile to its end and return the body bytes."""
    data = b''
    while True:
        chunk = rfile.read(3)
        if not chunk:
            return data
        data += chunk


@pytest.mark.parametrize(
    'chunks',
    (
        (b'xx\r\nxxxxyyyyy',),
        (b'xx\r\nxxxx', b'yyyyy'),
        tuple(b'xx\r\nxxxxyyyyy'[i : i + 1] for i in range(13)),
    ),
    ids=('single', 'two', 'one-byte-each'),
)
def test_chunked_body_arbitrary_boundaries(chunks):
    """Body reassembles identically regardless of chunk boundaries."""
    payload = make_chunked_body(chunks)
    rfile = ChunkedRFile(io.BytesIO(payload), maxlen=0)
    assert read_all(rfile) == b'xx\r\nxxxxyyyyy'
    assert rfile.trailers == {}
    assert rfile.trailer_errors == []
    # The connection stream is positioned right after the trailer
    # section, ready for the next request.
    assert rfile.rfile.read() == b''


def test_chunked_body_with_chunk_extensions():
    """Chunk extensions do not disturb body or trailer parsing."""
    payload = (
        b'8;key=value\r\nxx\r\nxxxx\r\n'
        b'5;foo=bar;baz\r\nyyyyy\r\n'
        b'0;done=yes\r\n'
        b'X-Checksum: abc123\r\n'
        b'\r\n'
    )
    rfile = ChunkedRFile(io.BytesIO(payload), maxlen=0)
    assert read_all(rfile) == b'xx\r\nxxxxyyyyy'
    assert rfile.trailers == {b'X-Checksum': b'abc123'}
    assert rfile.rfile.read() == b''


@pytest.mark.parametrize(
    'chunks',
    (
        (b'hello world',),
        (b'hello', b' ', b'world'),
        (b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o', b'r', b'l', b'd'),
    ),
    ids=('single', 'words', 'one-byte-each'),
)
def test_trailers_parsed_after_terminal_chunk(chunks):
    """Trailer fields become available once the body is fully read."""
    payload = make_chunked_body(
        chunks,
        (b'X-Checksum: abc123', b'X-Note: hello'),
    )
    rfile = ChunkedRFile(io.BytesIO(payload), maxlen=0)
    assert rfile.trailers is None
    assert read_all(rfile) == b'hello world'
    assert rfile.trailers == {
        b'X-Checksum': b'abc123',
        b'X-Note': b'hello',
    }


def test_trailer_view_unavailable_until_body_consumed():
    """The read-only view raises until the terminal chunk is validated."""
    payload = make_chunked_body((b'abc',), (b'X-Checksum: abc123',))
    rfile = ChunkedRFile(io.BytesIO(payload), maxlen=0)
    trailers = RequestTrailers(rfile)

    with pytest.raises(RuntimeError, match='fully consumed'):
        trailers['X-Checksum']
    with pytest.raises(RuntimeError, match='fully consumed'):
        len(trailers)
    with pytest.raises(RuntimeError, match='fully consumed'):
        list(trailers)

    assert rfile.read() == b'abc'

    assert trailers['X-Checksum'] == 'abc123'
    assert len(trailers) == 1
    assert dict(trailers) == {'X-Checksum': 'abc123'}


def test_trailer_view_lookup_is_case_insensitive():
    """Trailer field lookup works regardless of casing."""
    payload = make_chunked_body((b'abc',), (b'X-Checksum: abc123',))
    rfile = ChunkedRFile(io.BytesIO(payload), maxlen=0)
    trailers = RequestTrailers(rfile)
    rfile.read()

    assert trailers['x-checksum'] == 'abc123'
    assert trailers['X-CHECKSUM'] == 'abc123'
    assert trailers.get('X-Checksum') == 'abc123'
    assert trailers.get('missing') is None
    assert trailers.get('missing', 'default') == 'default'
    assert 'X-Checksum' in trailers
    assert 'missing' not in trailers


def test_trailer_view_is_read_only():
    """The trailer view exposes no mutation API."""
    rfile = ChunkedRFile(io.BytesIO(make_chunked_body((b'x',))), maxlen=0)
    trailers = RequestTrailers(rfile)
    rfile.read()

    for operation in (
        lambda: trailers.__setitem__('X-A', 'b'),
        lambda: trailers.__delitem__('X-A'),
        lambda: trailers.pop('X-A'),
        lambda: trailers.clear(),
        lambda: trailers.update({'X-A': 'b'}),
    ):
        with pytest.raises(AttributeError):
            operation()


@pytest.mark.parametrize(
    'field',
    (
        b'Content-Length: 5',
        b'Transfer-Encoding: chunked',
        b'Trailer: X-A',
        b'Host: example.com',
        b'Authorization: Basic eQ==',
        b'Proxy-Authorization: Basic eQ==',
        b'Cookie: a=b',
        b'Content-Type: text/plain',
        b'Content-Encoding: gzip',
        b'Connection: close',
    ),
)
def test_prohibited_trailer_fields_are_dropped(field):
    """Message framing, routing and auth fields never survive trailers."""
    payload = make_chunked_body((b'abc',), (field, b'X-Checksum: ok'))
    rfile = ChunkedRFile(io.BytesIO(payload), maxlen=0)
    rfile.read()

    assert rfile.trailers == {b'X-Checksum': b'ok'}
    assert len(rfile.trailer_errors) == 1
    assert 'Prohibited trailer field dropped' in rfile.trailer_errors[0]


def test_undeclared_trailer_fields_are_dropped():
    """Fields not announced via the Trailer header are dropped+reported."""
    payload = make_chunked_body(
        (b'abc',),
        (b'X-Checksum: abc123', b'X-Other: nope'),
    )
    rfile = ChunkedRFile(
        io.BytesIO(payload),
        maxlen=0,
        declared_trailer_fields=frozenset({b'x-checksum'}),
    )
    rfile.read()

    assert rfile.trailers == {b'X-Checksum': b'abc123'}
    assert rfile.trailer_errors == [
        'Undeclared trailer field dropped: X-Other',
    ]


def test_declared_but_missing_trailer_field_is_not_an_error():
    """A declared field the client never sends is simply absent."""
    payload = make_chunked_body((b'abc',), (b'X-Checksum: abc123',))
    rfile = ChunkedRFile(
        io.BytesIO(payload),
        maxlen=0,
        declared_trailer_fields=frozenset({b'x-checksum', b'x-extra'}),
    )
    rfile.read()

    assert rfile.trailers == {b'X-Checksum': b'abc123'}
    assert rfile.trailer_errors == []


def test_any_trailer_field_accepted_without_declaration():
    """Without a Trailer header, all non-prohibited fields are kept."""
    payload = make_chunked_body(
        (b'abc',),
        (b'X-Checksum: abc123', b'X-Anything: yes'),
    )
    rfile = ChunkedRFile(io.BytesIO(payload), maxlen=0)
    rfile.read()

    assert rfile.trailers == {
        b'X-Checksum': b'abc123',
        b'X-Anything': b'yes',
    }
    assert rfile.trailer_errors == []


def test_duplicate_trailer_fields_follow_header_rules():
    """Repeated trailer fields fold like regular headers do."""
    payload = make_chunked_body(
        (b'abc',),
        (
            b'Pragma: no-cache',
            b'Pragma: no-store',
            b'X-Once: first',
            b'X-Once: second',
        ),
    )
    rfile = ChunkedRFile(io.BytesIO(payload), maxlen=0)
    rfile.read()

    # Comma-separated headers fold, other repeats keep the last value,
    # exactly as HeaderReader treats regular header fields.
    assert rfile.trailers[b'Pragma'] == b'no-cache, no-store'
    assert rfile.trailers[b'X-Once'] == b'second'


def test_trailers_do_not_touch_regular_headers():
    """Trailer parsing never modifies the regular header dict."""
    inheaders = {b'X-Checksum': b'from-header'}
    payload = make_chunked_body((b'abc',), (b'X-Checksum: from-trailer',))
    rfile = ChunkedRFile(io.BytesIO(payload), maxlen=0)
    HeaderReader()(io.BytesIO(b'\r\n'), inheaders)
    rfile.read()

    assert inheaders == {b'X-Checksum': b'from-header'}
    assert rfile.trailers == {b'X-Checksum': b'from-trailer'}


def test_missing_trailer_terminator_fails():
    """A trailer section without the final CRLF is a hard failure."""
    payload = make_chunked_body((b'abc',))[:-2]  # strip final CRLF
    rfile = ChunkedRFile(io.BytesIO(payload), maxlen=0)

    with pytest.raises(ValueError, match='Illegal end of headers'):
        rfile.read()
    assert rfile.failed
    assert rfile.trailers is None


def test_malformed_trailer_line_fails():
    """A trailer line without a colon is a hard failure."""
    payload = make_chunked_body((b'abc',), (b'not a header',))
    rfile = ChunkedRFile(io.BytesIO(payload), maxlen=0)

    with pytest.raises(ValueError, match='Illegal header line'):
        rfile.read()
    assert rfile.failed


def test_bad_chunk_size_marks_failure():
    """A malformed chunk size marks the stream as failed."""
    rfile = ChunkedRFile(io.BytesIO(b'zz\r\nabc\r\n0\r\n\r\n'), maxlen=0)

    with pytest.raises(ValueError, match='Bad chunked transfer size'):
        rfile.read()
    assert rfile.failed


def test_oversized_trailer_section_fails():
    """The trailer section counts towards the maximum body size."""
    payload = make_chunked_body((b'abc',), (b'X-Checksum: ' + b'y' * 100,))
    rfile = ChunkedRFile(io.BytesIO(payload), maxlen=20)

    with pytest.raises((IOError, errors.MaxSizeExceeded)):
        rfile.read()
    assert rfile.failed


def make_request(rfile):
    """Build a bare HTTPRequest carrying the given body rfile."""
    req = object.__new__(HTTPRequest)
    req.rfile = rfile
    req.close_connection = False
    return req


def test_consume_chunked_remainder_drains_body_and_trailers():
    """Early-finishing apps leave the connection aligned for reuse."""
    next_request = b'GET / HTTP/1.1\r\nHost: x\r\n\r\n'
    payload = make_chunked_body(
        (b'unread body',),
        (b'X-Checksum: abc123',),
    ) + next_request
    raw = io.BytesIO(payload)
    rfile = ChunkedRFile(raw, maxlen=0)
    req = make_request(rfile)

    req._consume_chunked_remainder()

    assert not req.close_connection
    assert rfile.trailers == {b'X-Checksum': b'abc123'}
    assert raw.read() == next_request


def test_consume_chunked_remainder_closes_on_failure():
    """A failed body stream must not be reused for another request."""
    rfile = ChunkedRFile(io.BytesIO(b'zz\r\nabc\r\n0\r\n\r\n'), maxlen=0)
    req = make_request(rfile)

    req._consume_chunked_remainder()

    assert req.close_connection
    assert rfile.failed


def test_consume_chunked_remainder_closes_on_oversize():
    """An oversized remaining body must not be reused either."""
    payload = make_chunked_body((b'x' * 100,), (b'X-A: b',))
    rfile = ChunkedRFile(io.BytesIO(payload), maxlen=10)
    req = make_request(rfile)

    req._consume_chunked_remainder()

    assert req.close_connection
    assert rfile.failed


def test_consume_chunked_remainder_after_failed_read():
    """A stream that already failed mid-request closes the connection."""
    rfile = ChunkedRFile(io.BytesIO(b'zz\r\n'), maxlen=0)
    req = make_request(rfile)
    with pytest.raises(ValueError):
        rfile.read()

    req._consume_chunked_remainder()

    assert req.close_connection
