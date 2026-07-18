"""Network-boundary checks for ComfyUI-Manager state-changing APIs.

The Manager UI has historically relied on ``security_level`` and ComfyUI's
listen address.  Neither property identifies the client that sent a specific
request.  This module adds a second, independent boundary: privileged Manager
operations are accepted only from a direct loopback TCP peer.

Forwarding headers are deliberately *not* trusted.  A local reverse proxy can
make an Internet request appear to originate from 127.0.0.1, so any request
carrying common proxy headers is rejected even when its TCP peer is loopback.
Use a direct localhost connection or an SSH local-forward for administration.
"""

from functools import wraps
import inspect
import ipaddress
import logging
import os


_PROXY_HEADERS = frozenset({
    "forwarded",
    "via",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-port",
    "x-forwarded-proto",
    "x-real-ip",
    "cf-connecting-ip",
    "true-client-ip",
    "x-client-ip",
    "x-cluster-client-ip",
    "fly-client-ip",
    "fastly-client-ip",
})


def _peer_ip(request):
    """Return the actual TCP peer IP, without consulting HTTP headers."""
    transport = getattr(request, "transport", None)
    if transport is None:
        return None

    try:
        peername = transport.get_extra_info("peername")
    except (AttributeError, OSError, TypeError):
        return None

    if isinstance(peername, (tuple, list)) and peername:
        return peername[0]
    if isinstance(peername, str):
        return peername
    return None


def is_trusted_local_request(request):
    """Return True only for a direct, unproxied loopback TCP request.

    ``Host``, ``Forwarded`` and ``X-Forwarded-For`` cannot establish trust:
    clients may forge them.  Proxy headers are instead treated as evidence that
    a loopback peer may be forwarding a non-local client, and fail closed.
    """
    headers = getattr(request, "headers", {})
    try:
        header_names = {str(name).lower() for name in headers.keys()}
    except AttributeError:
        return False

    if header_names & _PROXY_HEADERS:
        return False

    address = _peer_ip(request)
    if not address:
        return False

    try:
        parsed = ipaddress.ip_address(address)
    except (TypeError, ValueError):
        return False

    # Python does not classify IPv4-mapped loopback (for example
    # ::ffff:127.0.0.1) as loopback, so normalize it explicitly.
    if parsed.version == 6 and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped

    return parsed.is_loopback


def resolve_file_within_directory(base_dir, subfolder, filename):
    """Resolve an existing file while preventing traversal and symlink escape.

    Both the candidate and the allowed base are canonicalized before the
    ``commonpath`` comparison.  This rejects absolute path overrides, ``..``
    traversal, cross-drive paths, and symlinks that resolve outside the output
    directory.
    """
    if not isinstance(base_dir, (str, os.PathLike)):
        raise TypeError("base_dir must be path-like")
    if not isinstance(subfolder, str) or not isinstance(filename, str):
        raise TypeError("subfolder and filename must be strings")
    if not filename or "\x00" in filename or "\x00" in subfolder:
        raise ValueError("invalid output path")

    base = os.path.realpath(os.fspath(base_dir))
    candidate = os.path.realpath(os.path.join(base, subfolder, filename))

    try:
        contained = os.path.commonpath((base, candidate)) == base
    except (TypeError, ValueError):
        contained = False

    if not contained:
        raise ValueError("output path escapes the configured directory")
    if not os.path.isfile(candidate):
        raise FileNotFoundError(candidate)

    return candidate


def local_only(handler):
    """Protect an aiohttp route so only direct localhost clients can call it."""
    @wraps(handler)
    async def wrapped(request, *args, **kwargs):
        if not is_trusted_local_request(request):
            from aiohttp import web

            peer = _peer_ip(request) or "unknown"
            logging.warning(
                "[ComfyUI-Manager] blocked non-local privileged request "
                "path=%s peer=%s",
                getattr(request, "path", "unknown"),
                peer,
            )
            return web.Response(
                status=403,
                text=(
                    "This privileged ComfyUI-Manager operation is available "
                    "only through a direct localhost connection."
                ),
            )

        result = handler(request, *args, **kwargs)
        if inspect.isawaitable(result):
            result = await result
        return result

    return wrapped
