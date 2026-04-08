"""
Unit tests for PtfGnmic client class.

Uses importlib to load ptf_gnmic.py directly, avoiding tests.common.__init__.py
import chain which requires the full sonic-mgmt test environment.
"""
import importlib.util
import os
import sys
import pytest
from unittest.mock import MagicMock

# Load ptf_gnmic module directly (bypass tests.common.__init__.py)
_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
_SPEC = importlib.util.spec_from_file_location("ptf_gnmic", os.path.join(_MODULE_DIR, "ptf_gnmic.py"))
_mod = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_mod)

PtfGnmic = _mod.PtfGnmic
PtfGnmicError = _mod.PtfGnmicError
GnmicConnectionError = _mod.GnmicConnectionError
GnmicCallError = _mod.GnmicCallError


@pytest.fixture
def mock_ptfhost():
    """Create a mock ptfhost with shell() method."""
    host = MagicMock()
    host.shell = MagicMock()
    return host


class TestConstructor:
    def test_constructor_defaults(self, mock_ptfhost):
        """PtfGnmic constructor stores correct defaults."""
        client = PtfGnmic(mock_ptfhost, "10.0.0.1:50052")
        assert client.target == "10.0.0.1:50052"
        assert client.plaintext is False
        assert client.ca_cert is None
        assert client.client_cert is None
        assert client.client_key is None

    def test_constructor_plaintext(self, mock_ptfhost):
        """PtfGnmic constructor with plaintext=True."""
        client = PtfGnmic(mock_ptfhost, "10.0.0.1:8080", plaintext=True)
        assert client.plaintext is True


class TestConfigureTls:
    def test_configure_tls_certificates(self, mock_ptfhost):
        """configure_tls_certificates stores certs and sets plaintext=False."""
        client = PtfGnmic(mock_ptfhost, "10.0.0.1:50052", plaintext=True)
        client.configure_tls_certificates("/ca.pem", "/cert.pem", "/key.pem")
        assert client.ca_cert == "/ca.pem"
        assert client.client_cert == "/cert.pem"
        assert client.client_key == "/key.pem"
        assert client.plaintext is False


class TestCapabilities:
    def test_capabilities_tls_command(self, mock_ptfhost):
        """capabilities() in TLS mode builds correct gnmic command."""
        client = PtfGnmic(mock_ptfhost, "10.0.0.1:50052")
        client.configure_tls_certificates(
            "/etc/ssl/certs/gnmiCA.cer",
            "/etc/ssl/certs/gnmiclient.cer",
            "/etc/ssl/certs/gnmiclient.key",
        )
        mock_ptfhost.shell.return_value = {
            "rc": 0,
            "stdout": '{"gnmi-version":"0.8.0"}',
            "stderr": "",
        }
        client.capabilities()
        assert mock_ptfhost.shell.call_count == 1
        cmd = mock_ptfhost.shell.call_args[0][0]
        assert "/usr/local/bin/gnmic" in cmd
        assert "-a 10.0.0.1:50052" in cmd
        assert "--tls-ca /etc/ssl/certs/gnmiCA.cer" in cmd
        assert "--tls-cert /etc/ssl/certs/gnmiclient.cer" in cmd
        assert "--tls-key /etc/ssl/certs/gnmiclient.key" in cmd
        assert "capabilities" in cmd
        assert "--format json" in cmd

    def test_capabilities_plaintext_command(self, mock_ptfhost):
        """capabilities() in plaintext mode uses --insecure flag."""
        client = PtfGnmic(mock_ptfhost, "10.0.0.1:8080", plaintext=True)
        mock_ptfhost.shell.return_value = {
            "rc": 0,
            "stdout": '{"gnmi-version":"0.8.0"}',
            "stderr": "",
        }
        client.capabilities()
        cmd = mock_ptfhost.shell.call_args[0][0]
        assert "--insecure" in cmd
        assert "--tls-ca" not in cmd

    def test_capabilities_parses_json(self, mock_ptfhost):
        """capabilities() returns parsed JSON dict on success."""
        client = PtfGnmic(mock_ptfhost, "10.0.0.1:50052")
        client.configure_tls_certificates("/ca.pem", "/cert.pem", "/key.pem")
        mock_ptfhost.shell.return_value = {
            "rc": 0,
            "stdout": '{"supported-encodings":["JSON_IETF","JSON","PROTO"],'
                      '"supported-models":[{"name":"sonic-db","organization":"SONiC","version":"1.0"}],'
                      '"gnmi-version":"0.8.0"}',
            "stderr": "",
        }
        result = client.capabilities()
        assert isinstance(result, dict)
        assert result["gnmi-version"] == "0.8.0"
        assert "JSON_IETF" in result["supported-encodings"]
        assert result["supported-models"][0]["name"] == "sonic-db"

    def test_capabilities_connection_error_raises(self, mock_ptfhost):
        """capabilities() raises GnmicConnectionError on connection failure."""
        client = PtfGnmic(mock_ptfhost, "10.0.0.1:50052")
        client.configure_tls_certificates("/ca.pem", "/cert.pem", "/key.pem")
        mock_ptfhost.shell.return_value = {
            "rc": 1,
            "stdout": "",
            "stderr": "connection refused",
        }
        with pytest.raises(GnmicConnectionError) as exc_info:
            client.capabilities()
        assert "connection refused" in str(exc_info.value)

    def test_capabilities_generic_error_raises(self, mock_ptfhost):
        """capabilities() raises GnmicCallError on generic non-zero rc."""
        client = PtfGnmic(mock_ptfhost, "10.0.0.1:50052", plaintext=True)
        mock_ptfhost.shell.return_value = {
            "rc": 1,
            "stdout": "",
            "stderr": "unknown flag --bad",
        }
        with pytest.raises(GnmicCallError) as exc_info:
            client.capabilities()
        assert "unknown flag" in str(exc_info.value)

    def test_capabilities_malformed_json_raises(self, mock_ptfhost):
        """capabilities() raises GnmicCallError on malformed JSON output."""
        client = PtfGnmic(mock_ptfhost, "10.0.0.1:50052", plaintext=True)
        mock_ptfhost.shell.return_value = {
            "rc": 0,
            "stdout": "this is not json",
            "stderr": "",
        }
        with pytest.raises(GnmicCallError) as exc_info:
            client.capabilities()
        assert "invalid JSON" in str(exc_info.value).lower() or "invalid json" in str(exc_info.value)
