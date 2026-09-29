import collections.abc as _c
import typing as _t
from abc import ABC, abstractmethod

class SNIRejected(Exception): ...

class SNISite:
    certificate: _t.Any
    private_key: _t.Any
    certificate_chain: _t.Any
    ciphers: _t.Any
    private_key_password: _c.Callable[[], bytes | str] | bytes | str | None
    client_verify_mode: str
    def __init__(
        self,
        certificate,
        private_key,
        certificate_chain: _t.Any | None = ...,
        ciphers: _t.Any | None = ...,
        *,
        private_key_password: _c.Callable[[], bytes | str]
        | bytes
        | str
        | None = ...,
        client_verify_mode: str = ...,
    ) -> None: ...

class SNIMap:
    missing_sni: str
    unknown_sni: str
    def __init__(
        self,
        sites: _c.Mapping[str, SNISite],
        *,
        missing_sni: str = ...,
        unknown_sni: str = ...,
    ) -> None: ...
    def __len__(self) -> int: ...
    def __contains__(self, hostname: str) -> bool: ...
    def items(self): ...
    def resolve(self, server_name: str | None) -> str | None: ...

class Adapter(ABC):
    certificate: _t.Any
    private_key: _t.Any
    certificate_chain: _t.Any
    ciphers: _t.Any
    private_key_password: _c.Callable[[], bytes | str] | bytes | str | None
    sni: SNIMap | None
    context: _t.Any

    @abstractmethod
    def __init__(
        self,
        certificate,
        private_key,
        certificate_chain: _t.Any | None = ...,
        ciphers: _t.Any | None = ...,
        *,
        private_key_password: _c.Callable[[], bytes | str]
        | bytes
        | str
        | None = ...,
        sni: SNIMap | _c.Mapping[str, SNISite] | None = ...,
    ): ...
    def bind(self, sock): ...
    @abstractmethod
    def wrap(self, sock): ...
    @abstractmethod
    def get_environ(self): ...
    @abstractmethod
    def makefile(self, sock, mode: str = ..., bufsize: int = ...): ...
    def _prompt_for_tls_password(self) -> str: ...
