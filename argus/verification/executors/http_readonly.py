"""Minimal read-only HTTP transport with DNS pinning and bounded streaming."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlsplit

import httpcore
from httpcore._backends.base import SOCKET_OPTION, NetworkStream
from httpcore._backends.sync import SyncBackend


class ResponseTooLarge(RuntimeError):
    pass


class PinnedNetworkBackend(SyncBackend):
    def __init__(self, host: str, pinned_ip: str) -> None:
        self.host = host
        self.pinned_ip = pinned_ip

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[SOCKET_OPTION] | None = None,
    ) -> NetworkStream:
        if host.lower().rstrip(".") != self.host:
            raise OSError("transport attempted an unapproved hostname")
        return super().connect_tcp(
            self.pinned_ip,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )


@dataclass(frozen=True)
class ReadonlyResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


class ReadonlyHttpExecutor:
    SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

    def request(
        self,
        *,
        method: str,
        url: str,
        host: str,
        pinned_ip: str,
        headers: tuple[tuple[str, str], ...],
        timeout_seconds: int,
        max_bytes: int,
    ) -> ReadonlyResponse:
        if method not in self.SAFE_METHODS:
            raise PermissionError("read-only executor rejected a non-safe method")
        backend = PinnedNetworkBackend(host, pinned_ip)
        parsed = urlsplit(url)
        default_port = 443 if parsed.scheme == "https" else 80
        header_host = f"[{host}]" if ":" in host else host
        host_header = header_host if parsed.port in {None, default_port} else f"{header_host}:{parsed.port}"
        timeout = float(timeout_seconds)
        pool = httpcore.ConnectionPool(
            network_backend=backend,
            retries=0,
            max_connections=1,
            max_keepalive_connections=0,
        )
        request = httpcore.Request(
            method,
            url,
            headers=[("Host", host_header), *headers],
            extensions={
                "timeout": {
                    "connect": timeout,
                    "read": timeout,
                    "write": timeout,
                    "pool": timeout,
                }
            },
        )
        response = pool.handle_request(request)
        body = bytearray()
        try:
            for chunk in response.iter_stream():
                if len(body) + len(chunk) > max_bytes:
                    raise ResponseTooLarge("response exceeded the remaining approved byte budget")
                body.extend(chunk)
        finally:
            response.close()
            pool.close()
        decoded_headers = tuple(
            (name.decode("ascii", errors="replace"), value.decode("latin-1", errors="replace"))
            for name, value in response.headers
        )
        return ReadonlyResponse(response.status, decoded_headers, bytes(body))
