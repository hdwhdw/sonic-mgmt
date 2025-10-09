#!/bin/bash
#
# Quick test script for csonic_network module
# This script manually tests the functionality without ansible
#

set -e

TEST_VM_NAME="VM0200"
TEST_VM_SET="sonic-test"
MGMT_BRIDGE="br-mgmt"
BASE_CTN="net_${TEST_VM_SET}_${TEST_VM_NAME}"
SONIC_CTN="sonic_${TEST_VM_SET}_${TEST_VM_NAME}"

echo "=========================================="
echo "SONiC Network Test Setup Script"
echo "=========================================="
echo ""

# Cleanup function
cleanup() {
    echo "Cleaning up existing containers and bridges..."
    docker rm -f ${SONIC_CTN} ${BASE_CTN} 2>/dev/null || true
    for i in {0..3}; do
        sudo ovs-vsctl del-br br-${TEST_VM_NAME}-$i 2>/dev/null || true
    done
    echo "Cleanup complete."
}

# Check if cleanup requested
if [ "$1" == "cleanup" ]; then
    cleanup
    exit 0
fi

# Step 1: Create management bridge if needed
echo "Step 1: Ensuring management bridge exists..."
if ! brctl show | grep -q "^${MGMT_BRIDGE}"; then
    echo "  Creating management bridge ${MGMT_BRIDGE}..."
    sudo brctl addbr ${MGMT_BRIDGE}
    sudo ip link set ${MGMT_BRIDGE} up
    sudo ip addr add 10.250.0.1/24 dev ${MGMT_BRIDGE} 2>/dev/null || echo "  (IP already assigned)"
else
    echo "  Management bridge ${MGMT_BRIDGE} already exists."
fi

# Step 2: Create OVS bridges
echo ""
echo "Step 2: Creating OVS bridges for front panel ports..."
for i in {0..3}; do
    if ! sudo ovs-vsctl br-exists br-${TEST_VM_NAME}-$i; then
        sudo ovs-vsctl add-br br-${TEST_VM_NAME}-$i
        echo "  Created br-${TEST_VM_NAME}-$i"
    else
        echo "  br-${TEST_VM_NAME}-$i already exists"
    fi
done

# Step 3: Create base container
echo ""
echo "Step 3: Creating base network container..."
docker run -d \
    --name ${BASE_CTN} \
    --privileged \
    --network none \
    --cap-add NET_ADMIN \
    debian:bookworm \
    sleep infinity

echo "  Container ${BASE_CTN} created."

# Step 4: Get container PID
echo ""
echo "Step 4: Getting container PID..."
BASE_PID=$(docker inspect ${BASE_CTN} -f '{{.State.Pid}}')
echo "  PID: ${BASE_PID}"

# Step 5: Create veth pairs and inject interfaces
echo ""
echo "Step 5: Creating and injecting network interfaces..."

# Management interface (eth0)
echo "  Creating management interface..."
if ! ip link show ${TEST_VM_NAME}-m &>/dev/null; then
    sudo ip link add ${TEST_VM_NAME}-m type veth peer name ${TEST_VM_NAME}-tmp0
    sudo ip link set ${TEST_VM_NAME}-tmp0 netns ${BASE_PID}
    sudo nsenter -t ${BASE_PID} -n ip link set ${TEST_VM_NAME}-tmp0 name eth0
    sudo nsenter -t ${BASE_PID} -n ip link set eth0 up
    sudo ip link set ${TEST_VM_NAME}-m up
    sudo brctl addif ${MGMT_BRIDGE} ${TEST_VM_NAME}-m
    echo "    ${TEST_VM_NAME}-m <-> eth0 (added to ${MGMT_BRIDGE})"
fi

# Front panel interfaces (Ethernet0, Ethernet4, Ethernet8, Ethernet12)
for i in {0..3}; do
    FP_NAME="${TEST_VM_NAME}-t$i"
    TMP_NAME="${TEST_VM_NAME}-tmp$((i+1))"
    SONIC_NAME="Ethernet$((i*4))"
    BRIDGE_NAME="br-${TEST_VM_NAME}-$i"

    echo "  Creating front panel interface $i..."
    if ! ip link show ${FP_NAME} &>/dev/null; then
        sudo ip link add ${FP_NAME} type veth peer name ${TMP_NAME}
        sudo ip link set dev ${FP_NAME} mtu 9214
        sudo ip link set dev ${TMP_NAME} mtu 9214
        sudo ip link set ${TMP_NAME} netns ${BASE_PID}
        sudo nsenter -t ${BASE_PID} -n ip link set ${TMP_NAME} name ${SONIC_NAME}
        sudo nsenter -t ${BASE_PID} -n ip link set ${SONIC_NAME} up
        sudo ip link set ${FP_NAME} up
        sudo ovs-vsctl add-port ${BRIDGE_NAME} ${FP_NAME}
        echo "    ${FP_NAME} <-> ${SONIC_NAME} (added to ${BRIDGE_NAME})"
    fi
done

# Backplane interface
echo "  Creating backplane interface..."
BP_NAME="${TEST_VM_NAME}-back"
if ! ip link show ${BP_NAME} &>/dev/null; then
    sudo ip link add ${BP_NAME} type veth peer name ${TEST_VM_NAME}-tmp5
    sudo ip link set ${TEST_VM_NAME}-tmp5 netns ${BASE_PID}
    sudo nsenter -t ${BASE_PID} -n ip link set ${TEST_VM_NAME}-tmp5 name eth_bp
    sudo nsenter -t ${BASE_PID} -n ip link set eth_bp up
    sudo ip link set ${BP_NAME} up
    echo "    ${BP_NAME} <-> eth_bp"
fi

# Step 6: Verify interfaces in base container
echo ""
echo "Step 6: Verifying interfaces in base container..."
echo "========================================"
sudo nsenter -t ${BASE_PID} -n ip link show | grep -E "^[0-9]+:" | grep -E "(eth0|Ethernet|eth_bp)"
echo "========================================"

# Step 7: Start SONiC container
echo ""
echo "Step 7: Starting SONiC container sharing network namespace..."
docker run -d \
    --name ${SONIC_CTN} \
    --privileged \
    --network container:${BASE_CTN} \
    --memory 2G \
    --memory-swap 4G \
    docker-sonic-vs:latest

echo "  Container ${SONIC_CTN} started."

# Step 8: Wait and check SONiC
echo ""
echo "Step 8: Waiting for SONiC to initialize (10 seconds)..."
sleep 10

echo ""
echo "Checking SONiC can see the interfaces..."
echo "========================================"
docker exec ${SONIC_CTN} ip link show | grep -E "^[0-9]+:" | grep -E "(eth0|Ethernet|eth_bp)"
echo "========================================"

# Step 9: Check OVS bridge connectivity
echo ""
echo "Step 9: Verifying OVS bridge connections..."
for i in {0..3}; do
    echo "  br-${TEST_VM_NAME}-$i ports:"
    sudo ovs-vsctl list-ports br-${TEST_VM_NAME}-$i | sed 's/^/    /'
done

# Summary
echo ""
echo "=========================================="
echo "SUCCESS! SONiC Network Setup Complete"
echo "=========================================="
echo ""
echo "Base container:  ${BASE_CTN}"
echo "SONiC container: ${SONIC_CTN}"
echo ""
echo "Network Topology:"
echo "  ${TEST_VM_NAME}-m      <-> eth0       <-> ${MGMT_BRIDGE}"
echo "  ${TEST_VM_NAME}-t0     <-> Ethernet0  <-> br-${TEST_VM_NAME}-0"
echo "  ${TEST_VM_NAME}-t1     <-> Ethernet4  <-> br-${TEST_VM_NAME}-1"
echo "  ${TEST_VM_NAME}-t2     <-> Ethernet8  <-> br-${TEST_VM_NAME}-2"
echo "  ${TEST_VM_NAME}-t3     <-> Ethernet12 <-> br-${TEST_VM_NAME}-3"
echo "  ${TEST_VM_NAME}-back   <-> eth_bp"
echo ""
echo "Inspect containers:"
echo "  docker exec -it ${SONIC_CTN} bash"
echo "  docker exec ${SONIC_CTN} ip addr"
echo "  docker exec ${SONIC_CTN} supervisorctl status"
echo ""
echo "Cleanup when done:"
echo "  $0 cleanup"
echo ""
