import collections.abc as _c
import typing as _t
from abc import ABC, abstractmethod

SNI_FALLBACK_DEFAULT: str
SNI_FALLBACK_REJECT: str

class SniSiteConfig:
    hostname: _t.Any
    certificate: _t.Any
    private_key: _t.Any
    certificate_chain: _t.Any
    ciphers: _t.Any
    private_key_password: _t.Any
    verify_mode: _t.Any
    context: _t.Any
    def __init__(
        self,
        hostname,
        certificate,
        private_key,
        certificate_chain: _t.Any | None = ...,
        ciphers: _t.Any | None = ...,
        *,
        private_key_password: _t.Any | None = ...,
        verify_mode: _t.Any | None = ...,
    ) -> None: ...

class Adapter(ABC):
    certificate: _t.Any
    private_key: _t.Any
    certificate_chain: _t.Any
    ciphers: _t.Any
    private_key_password: _c.Callable[[], bytes | str] | bytes | str | None
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
    ): ...
    def bind(self, sock): ...
    @property
    def sni_sites(self) -> _c.Mapping[str, SniSiteConfig]: ...
    @property
    def sni_missing(self) -> str: ...
    @sni_missing.setter
    def sni_missing(self, policy: str) -> None: ...
    @property
    def sni_unknown(self) -> str: ...
    @sni_unknown.setter
    def sni_unknown(self, policy: str) -> None: ...
    def add_sni_site(
        self,
        hostname,
        certificate,
        private_key,
        certificate_chain: _t.Any | None = ...,
        ciphers: _t.Any | None = ...,
        *,
        private_key_password: _t.Any | None = ...,
        verify_mode: _t.Any | None = ...,
    ) -> SniSiteConfig: ...
    @abstractmethod
    def wrap(self, sock): ...
    @abstractmethod
    def get_environ(self): ...
    @abstractmethod
    def makefile(self, sock, mode: str = ..., bufsize: int = ...): ...
    def _prompt_for_tls_password(self) -> str: ...
