"""
Unit tests for GnmiFixture integration with PtfGnmic.

Verifies that grpc_fixtures.py correctly integrates PtfGnmic into the
GnmiFixture dataclass and both gnmi_tls / gnmi_plaintext fixture functions.

Uses importlib to load grpc_fixtures.py directly, avoiding the heavy
tests.common.__init__.py import chain.
"""
import importlib.util
import inspect
import os
import sys
import pytest
from dataclasses import fields as dataclass_fields
from unittest.mock import MagicMock

# Stub out heavy dependencies before importing grpc_fixtures
_STUBS = [
    "tests", "tests.common", "tests.common.cert_utils",
    "tests.common.grpc_config", "tests.common.gu_utils",
    "tests.common.helpers", "tests.common.helpers.gnmi_utils",
    "tests.common.ptf_grpc", "tests.common.ptf_gnoi",
    "tests.common.ptf_gnmic",
]
for mod_name in _STUBS:
    if mod_name not in sys.modules:
        sys.modules[mod_name] = MagicMock()

# Load grpc_fixtures via importlib
_MODULE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
_SPEC = importlib.util.spec_from_file_location(
    "grpc_fixtures",
    os.path.join(_MODULE_DIR, "grpc_fixtures.py"),
)
_mod = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_mod)

GnmiFixture = _mod.GnmiFixture
CertPaths = _mod.CertPaths


class TestGnmiFixtureDataclass:
    """Verify GnmiFixture dataclass has the gnmic field (FIX-01)."""

    def test_gnmic_field_exists(self):
        """GnmiFixture has a field named 'gnmic'."""
        field_names = [f.name for f in dataclass_fields(GnmiFixture)]
        assert "gnmic" in field_names

    def test_gnmic_field_after_gnoi(self):
        """gnmic field comes after gnoi in field order."""
        field_names = [f.name for f in dataclass_fields(GnmiFixture)]
        assert field_names.index("gnmic") > field_names.index("gnoi")

    def test_gnmic_field_is_required(self):
        """gnmic field has no default — it is required."""
        mock_grpc = MagicMock()
        mock_gnoi = MagicMock()
        with pytest.raises(TypeError):
            GnmiFixture(
                host="10.0.0.1",
                port=50052,
                tls=True,
                cert_paths=None,
                grpc=mock_grpc,
                gnoi=mock_gnoi,
            )

    def test_construct_with_gnmic(self):
        """GnmiFixture can be constructed with gnmic= argument."""
        mock_grpc = MagicMock()
        mock_gnoi = MagicMock()
        mock_gnmic = MagicMock()
        cert_paths = CertPaths(ca_cert="/ca", client_cert="/cert", client_key="/key")
        fixture = GnmiFixture(
            host="10.0.0.1",
            port=50052,
            tls=True,
            cert_paths=cert_paths,
            grpc=mock_grpc,
            gnoi=mock_gnoi,
            gnmic=mock_gnmic,
        )
        assert fixture.gnmic is mock_gnmic
        assert fixture.grpc is mock_grpc
        assert fixture.gnoi is mock_gnoi

    def test_construct_without_gnmic_raises(self):
        """GnmiFixture without gnmic= raises TypeError (required field)."""
        mock_grpc = MagicMock()
        mock_gnoi = MagicMock()
        with pytest.raises(TypeError):
            GnmiFixture(
                host="10.0.0.1",
                port=50052,
                tls=True,
                cert_paths=None,
                grpc=mock_grpc,
                gnoi=mock_gnoi,
            )

    def test_existing_fields_unchanged(self):
        """Original fields (host, port, tls, cert_paths, grpc, gnoi) still present."""
        field_names = [f.name for f in dataclass_fields(GnmiFixture)]
        for expected in ["host", "port", "tls", "cert_paths", "grpc", "gnoi"]:
            assert expected in field_names, f"Missing field: {expected}"


class TestGnmiTlsFixtureSource:
    """Verify gnmi_tls constructs PtfGnmic correctly (FIX-02) via source inspection."""

    def test_gnmi_tls_constructs_gnmic_client(self):
        """gnmi_tls source contains PtfGnmic construction with TLS."""
        source = inspect.getsource(_mod.gnmi_tls)
        assert "PtfGnmic(ptfhost, target, plaintext=False)" in source

    def test_gnmi_tls_configures_tls_certs(self):
        """gnmi_tls source calls configure_tls_certificates on gnmic_client."""
        source = inspect.getsource(_mod.gnmi_tls)
        assert "gnmic_client.configure_tls_certificates(" in source
        assert "ca_cert=cert_paths.ca_cert" in source
        assert "client_cert=cert_paths.client_cert" in source
        assert "client_key=cert_paths.client_key" in source

    def test_gnmi_tls_passes_gnmic_to_fixture(self):
        """gnmi_tls source passes gnmic=gnmic_client to GnmiFixture."""
        source = inspect.getsource(_mod.gnmi_tls)
        assert "gnmic=gnmic_client" in source


class TestGnmiPlaintextFixtureSource:
    """Verify gnmi_plaintext constructs PtfGnmic correctly."""

    def test_gnmi_plaintext_constructs_gnmic_client(self):
        """gnmi_plaintext source contains PtfGnmic with plaintext=True."""
        source = inspect.getsource(_mod.gnmi_plaintext)
        assert "PtfGnmic(ptfhost, target, plaintext=True)" in source

    def test_gnmi_plaintext_no_tls_config(self):
        """gnmi_plaintext source does NOT call configure_tls_certificates for gnmic."""
        source = inspect.getsource(_mod.gnmi_plaintext)
        assert "gnmic_client.configure_tls_certificates" not in source

    def test_gnmi_plaintext_passes_gnmic_to_fixture(self):
        """gnmi_plaintext source passes gnmic=gnmic_client to GnmiFixture."""
        source = inspect.getsource(_mod.gnmi_plaintext)
        assert "gnmic=gnmic_client" in source


class TestExistingPatternsPreserved:
    """Verify existing grpc/gnoi patterns unchanged (FIX-03)."""

    def test_grpc_field_exists(self):
        """grpc field still present on GnmiFixture."""
        field_names = [f.name for f in dataclass_fields(GnmiFixture)]
        assert "grpc" in field_names

    def test_gnoi_field_exists(self):
        """gnoi field still present on GnmiFixture."""
        field_names = [f.name for f in dataclass_fields(GnmiFixture)]
        assert "gnoi" in field_names

    def test_gnmi_tls_still_constructs_ptf_grpc(self):
        """gnmi_tls source still creates PtfGrpc client."""
        source = inspect.getsource(_mod.gnmi_tls)
        assert "PtfGrpc(ptfhost, target, plaintext=False)" in source

    def test_gnmi_tls_still_constructs_ptf_gnoi(self):
        """gnmi_tls source still creates PtfGnoi wrapper."""
        source = inspect.getsource(_mod.gnmi_tls)
        assert "PtfGnoi(client)" in source
