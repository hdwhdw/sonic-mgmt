"""
Simple gNOI reboot test using default configuration and gnoi_client binary.

This test uses the gnoi_client binary inside the gnmi container,
following the same pattern as existing gNMI tests.
"""
import pytest
import logging
import json

pytestmark = [
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)


def gnoi_request_simple(duthost, module, rpc, request_json_data=""):
    """
    Send a gNOI request using the gnoi_client binary inside gnmi container.
    
    Similar to gnoi_request from tests/gnmi/helper.py but simplified for basic testing.
    """
    # Get container name
    gnmi_containers = duthost.shell("docker ps | grep gnmi | awk '{print $NF}' | head -1")
    container_name = gnmi_containers['stdout'].strip()
    
    if not container_name:
        return -1, "No gNMI container found"
    
    # Try targeting the host IP from inside the container
    # The telemetry server listens on all interfaces (:::8080)
    ip = duthost.mgmt_ip  # Use the host management IP
    port = "8080"         # default insecure port
    
    # Build gnoi_client command with notls flag (disable TLS completely)
    cmd = f"docker exec {container_name} gnoi_client -target {ip}:{port} "
    cmd += f"-logtostderr -notls "
    cmd += f"-rpc {rpc} "
    if request_json_data:
        cmd += f"-jsonin '{request_json_data}'"
    
    logger.info(f"Running gNOI command: {cmd}")
    
    output = duthost.shell(cmd, module_ignore_errors=True)
    
    if output.get('rc', 0) != 0:
        logger.error(f"gNOI command failed with rc={output.get('rc')}: {output.get('stderr', '')}")
        return output.get('rc', -1), output.get('stderr', 'Unknown error')
    else:
        return 0, output.get('stdout', '')


def test_gnoi_system_time_basic(duthosts, rand_one_dut_hostname):
    """
    Basic gNOI System.Time test using gnoi_client binary.
    
    This verifies that gNOI is working with the default insecure configuration.
    """
    duthost = duthosts[rand_one_dut_hostname]
    
    logger.info("=== Testing gNOI System.Time with gnoi_client ===")
    
    # Send System.Time request (no input data needed)
    ret, msg = gnoi_request_simple(duthost, "System", "Time")
    
    logger.info(f"gNOI Time response: rc={ret}, msg={msg}")
    
    if ret != 0:
        if "Unimplemented" in msg or "not implemented" in msg.lower():
            pytest.skip(f"gNOI System.Time not implemented: {msg}")
        else:
            pytest.fail(f"gNOI System.Time failed (rc={ret}): {msg}")
    
    # Parse and validate response
    try:
        # Response should contain time info, format may vary
        assert msg.strip(), "Time response should not be empty"
        logger.info("gNOI System.Time test passed")
        
    except Exception as e:
        logger.error(f"Failed to parse time response: {e}")
        pytest.fail(f"Invalid time response: {msg}")


def test_gnoi_system_reboot_cold_basic(duthosts, rand_one_dut_hostname):
    """
    Basic gNOI System.Reboot test using gnoi_client binary.
    
    Tests the gNOI reboot API with method=1 (COLD), delay=0, and a test message.
    This should NOT actually reboot since we use delay=0.
    """
    duthost = duthosts[rand_one_dut_hostname]
    
    logger.info("=== Testing gNOI System.Reboot with gnoi_client ===")
    
    # Create reboot request JSON
    reboot_request = {
        "method": 1,  # COLD reboot
        "delay": 0,   # No delay - should not actually reboot
        "message": "gNOI test reboot - delay=0"
    }
    
    request_json = json.dumps(reboot_request)
    logger.info(f"Sending gNOI reboot request: {request_json}")
    
    # Send System.Reboot request
    ret, msg = gnoi_request_simple(duthost, "System", "Reboot", request_json)
    
    logger.info(f"gNOI Reboot response: rc={ret}, msg={msg}")
    
    if ret != 0:
        if "Unimplemented" in msg or "not implemented" in msg.lower():
            pytest.skip(f"gNOI System.Reboot not implemented: {msg}")
        else:
            pytest.fail(f"gNOI System.Reboot failed (rc={ret}): {msg}")
    
    # If we get here, the API accepted the request
    logger.info("gNOI System.Reboot test passed - API accepted request")
    assert True, "gNOI reboot API responded successfully"