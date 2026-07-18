import asyncio
import os
import pathlib
import sys
import tempfile
import types
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "glob"))

from manager_security import (  # noqa: E402
    is_trusted_local_request,
    local_only,
    resolve_file_within_directory,
)


class FakeTransport:
    def __init__(self, peername):
        self.peername = peername

    def get_extra_info(self, name):
        return self.peername if name == "peername" else None


class FakeRequest:
    path = "/manager/queue/install"

    def __init__(self, peername, headers=None):
        self.transport = FakeTransport(peername)
        self.headers = headers or {}


class LocalRequestTests(unittest.TestCase):
    def test_ipv4_loopback_is_allowed(self):
        request = FakeRequest(("127.0.0.1", 54321))
        self.assertTrue(is_trusted_local_request(request))

    def test_ipv6_loopback_is_allowed(self):
        request = FakeRequest(("::1", 54321, 0, 0))
        self.assertTrue(is_trusted_local_request(request))

    def test_ipv4_mapped_loopback_is_allowed(self):
        request = FakeRequest(("::ffff:127.0.0.1", 54321, 0, 0))
        self.assertTrue(is_trusted_local_request(request))

    def test_private_and_public_peers_are_denied(self):
        for address in ("172.17.0.1", "10.0.0.8", "203.0.113.9"):
            with self.subTest(address=address):
                request = FakeRequest((address, 54321))
                self.assertFalse(is_trusted_local_request(request))

    def test_proxy_headers_are_denied_even_for_loopback_peer(self):
        for header in (
            "Forwarded",
            "X-Forwarded-For",
            "X-Real-IP",
            "CF-Connecting-IP",
            "Via",
        ):
            with self.subTest(header=header):
                request = FakeRequest(("127.0.0.1", 54321), {header: "127.0.0.1"})
                self.assertFalse(is_trusted_local_request(request))

    def test_forged_host_does_not_make_remote_peer_local(self):
        request = FakeRequest(("203.0.113.9", 54321), {"Host": "127.0.0.1:8188"})
        self.assertFalse(is_trusted_local_request(request))

    def test_missing_transport_fails_closed(self):
        request = FakeRequest(("127.0.0.1", 54321))
        request.transport = None
        self.assertFalse(is_trusted_local_request(request))

    def test_invalid_peer_type_fails_closed(self):
        request = FakeRequest((object(), 54321))
        self.assertFalse(is_trusted_local_request(request))

    def test_transport_type_error_fails_closed(self):
        class BrokenTransport:
            def get_extra_info(self, name):
                raise TypeError("broken transport")

        request = FakeRequest(("127.0.0.1", 54321))
        request.transport = BrokenTransport()
        self.assertFalse(is_trusted_local_request(request))

    def test_decorator_preserves_local_async_handler(self):
        @local_only
        async def handler(request):
            return "ok"

        result = asyncio.run(handler(FakeRequest(("127.0.0.1", 54321))))
        self.assertEqual(result, "ok")

    def test_decorator_returns_403_without_calling_remote_handler(self):
        called = False

        @local_only
        async def handler(request):
            nonlocal called
            called = True
            return "unsafe"

        class FakeResponse:
            def __init__(self, status, text):
                self.status = status
                self.text = text

        fake_aiohttp = types.ModuleType("aiohttp")
        fake_aiohttp.web = types.SimpleNamespace(Response=FakeResponse)

        with mock.patch.dict(sys.modules, {"aiohttp": fake_aiohttp}):
            result = asyncio.run(handler(FakeRequest(("203.0.113.9", 54321))))

        self.assertFalse(called)
        self.assertEqual(result.status, 403)


class RouteCoverageTests(unittest.TestCase):
    def test_privileged_routes_have_local_only_decorator(self):
        source = (ROOT / "glob" / "manager_server.py").read_text(encoding="utf-8")
        function_names = {
            "fetch_updates",
            "fetch_customnode_list",
            "update_all",
            "remove_snapshot",
            "restore_snapshot",
            "save_snapshot",
            "reinstall_custom_node",
            "reset_queue",
            "install_custom_node",
            "queue_start",
            "fix_custom_node",
            "install_custom_node_git_url",
            "install_custom_node_pip",
            "uninstall_custom_node",
            "update_custom_node",
            "update_comfyui",
            "comfyui_versions",
            "comfyui_switch_version",
            "disable_node",
            "install_model",
            "restart",
        }

        for name in function_names:
            with self.subTest(name=name):
                self.assertRegex(
                    source,
                    rf"@routes\.(?:get|post)\([^\n]+\)\n@local_only\n(?:async )?def {name}\(",
                )

    def test_sensitive_share_routes_have_local_only_decorator(self):
        source = (ROOT / "glob" / "share_3rdparty.py").read_text(encoding="utf-8")
        function_names = {
            "share_option",
            "api_get_openart_auth",
            "api_set_openart_auth",
            "api_get_matrix_auth",
            "api_get_youml_settings",
            "api_set_youml_settings",
            "api_get_comfyworkflows_auth",
            "set_esheep_workflow_and_images",
            "get_esheep_workflow_and_images",
            "share_art",
        }

        for name in function_names:
            with self.subTest(name=name):
                self.assertRegex(
                    source,
                    (
                        r"@PromptServer\.instance\.routes\.(?:get|post)\([^\n]+\)\n"
                        rf"@local_only\nasync def {name}\("
                    ),
                )

    def test_share_route_uses_contained_path_resolver(self):
        source = (ROOT / "glob" / "share_3rdparty.py").read_text(encoding="utf-8")
        self.assertIn("resolve_file_within_directory(", source)

    def test_new_install_security_default_is_strong(self):
        source = (ROOT / "glob" / "manager_core.py").read_text(encoding="utf-8")
        self.assertNotIn("default_conf.get('security_level', 'normal')", source)
        self.assertGreaterEqual(source.count("'security_level': 'strong'"), 1)


class ContainedPathTests(unittest.TestCase):
    def test_nested_file_is_allowed(self):
        with tempfile.TemporaryDirectory() as root:
            nested = pathlib.Path(root, "nested")
            nested.mkdir()
            target = nested / "result.png"
            target.write_bytes(b"image")

            resolved = resolve_file_within_directory(root, "nested", "result.png")
            self.assertEqual(resolved, os.path.realpath(target))

    def test_parent_traversal_is_denied(self):
        with tempfile.TemporaryDirectory() as parent:
            base = pathlib.Path(parent, "output")
            outside = pathlib.Path(parent, "outside")
            base.mkdir()
            outside.mkdir()
            (outside / "secret.txt").write_text("secret", encoding="utf-8")

            with self.assertRaises(ValueError):
                resolve_file_within_directory(base, "../outside", "secret.txt")

    def test_absolute_filename_is_denied(self):
        with tempfile.TemporaryDirectory() as parent:
            base = pathlib.Path(parent, "output")
            base.mkdir()
            outside = pathlib.Path(parent, "secret.txt")
            outside.write_text("secret", encoding="utf-8")

            with self.assertRaises(ValueError):
                resolve_file_within_directory(base, "", str(outside))

    def test_symlink_escape_is_denied(self):
        with tempfile.TemporaryDirectory() as parent:
            base = pathlib.Path(parent, "output")
            outside = pathlib.Path(parent, "outside")
            base.mkdir()
            outside.mkdir()
            (outside / "secret.txt").write_text("secret", encoding="utf-8")
            (base / "link").symlink_to(outside, target_is_directory=True)

            with self.assertRaises(ValueError):
                resolve_file_within_directory(base, "link", "secret.txt")

    def test_missing_file_is_denied(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(FileNotFoundError):
                resolve_file_within_directory(root, "", "missing.png")


if __name__ == "__main__":
    unittest.main()
