#!/usr/bin/env bash
# Two-node netns topology for the M0 e2e harness (see ../run.sh).
#
# Layout:
#
#   root netns
#   ┌─────────────────────────────────────────────────────────┐
#   │  e2e-br0 (10.99.0.0/24)                                  │
#   │   ├─ veth-broker (10.99.0.1) ── mosquitto + mqtt_stub.py │
#   │   ├─ veth-a-out  (10.99.0.11) ─┐                         │
#   │   └─ veth-b-out  (10.99.0.12) ─┼─┐                       │
#   └─────────────────────────────────┼─┼───────────────────────┘
#                                      │ │
#            netns e2e-node-a ────────┘ │      netns e2e-node-b
#            veth-a-in (10.99.0.11)     └───── veth-b-in (10.99.0.12)
#            + NetManager's own goProxyBridge/TUN/container veths,
#              created by NetManager itself once it registers.
#
# Each "container" is a plain `unshare --net` process (no docker needed):
# NetManager only needs a PID with its own netns to attach a peer veth to.

set -euo pipefail

BRIDGE=e2e-br0
BROKER_IP=10.99.0.1
NODE_A_NETNS=e2e-node-a
NODE_B_NETNS=e2e-node-b
NODE_A_IP=10.99.0.11
NODE_B_IP=10.99.0.12

topology_up() {
	ip link add "$BRIDGE" type bridge
	ip addr add "${BROKER_IP}/24" dev "$BRIDGE"
	ip link set "$BRIDGE" up

	ip netns add "$NODE_A_NETNS"
	ip netns add "$NODE_B_NETNS"

	_attach_node "$NODE_A_NETNS" veth-a-out veth-a-in "$NODE_A_IP"
	_attach_node "$NODE_B_NETNS" veth-b-out veth-b-in "$NODE_B_IP"

	# loopback up in each node netns, NetManager/its deployed containers need it
	ip netns exec "$NODE_A_NETNS" ip link set lo up
	ip netns exec "$NODE_B_NETNS" ip link set lo up
}

_attach_node() {
	local netns=$1 out=$2 in=$3 ip_addr=$4
	ip link add "$out" type veth peer name "$in"
	ip link set "$out" master "$BRIDGE"
	ip link set "$out" up
	ip link set "$in" netns "$netns"
	ip netns exec "$netns" ip addr add "${ip_addr}/24" dev "$in"
	ip netns exec "$netns" ip link set "$in" up
}

topology_down() {
	ip netns del "$NODE_A_NETNS" 2>/dev/null || true
	ip netns del "$NODE_B_NETNS" 2>/dev/null || true
	ip link del "$BRIDGE" 2>/dev/null || true
}

# spawn_container <netns> -> prints the PID of a `sleep infinity` process
# running in its own fresh network namespace inside the node's netns. That
# PID is what NetManager's /container/deploy expects (it calls
# netns.GetFromPid on it - see env.Environment.execInsideNs).
#
# `unshare --net` with no `--fork` execs sleep directly in place rather than
# forking a child, so the PID bash captures via $! from the backgrounded
# `ip netns exec` job is the exact PID that ends up owning the new netns -
# no PID-namespace translation to worry about, since only --net is unshared.
spawn_container() {
	local node_netns=$1
	ip netns exec "$node_netns" unshare --net -- sleep infinity &
	echo $!
}
