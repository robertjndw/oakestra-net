#!/usr/bin/env bash
# M0 e2e harness: two node-net-manager instances on one Linux host, talking
# real MQTT, exchanging real traffic through the semantic overlay - with the
# eBPF fast path either attached or not, so the same topology is the A/B
# switch the plan's "Verification" section asks for.
#
# Usage:
#   sudo ./run.sh baseline   # EbpfEnabled=false, pure ProxyTUN
#   sudo ./run.sh ebpf       # EbpfEnabled=true
#
# Requires (Linux only): ip/iproute2, unshare, mosquitto, python3 with
# paho-mqtt (pip install paho-mqtt), iperf3, go. Not runnable on macOS - the
# eBPF programs and network namespaces this depends on are Linux-only.
#
# This has not been run end-to-end in the environment that wrote it (no
# Linux host was available); treat first run as a debugging session, not a
# known-good script. NOTE comments below flag the parts most likely to need
# a fix on first try.

set -euo pipefail

if [[ "$(id -u)" != "0" ]]; then
	echo "must run as root (netns/veth/TC all need CAP_NET_ADMIN)" >&2
	exit 1
fi

MODE=${1:-}
if [[ "$MODE" != "baseline" && "$MODE" != "ebpf" ]]; then
	echo "usage: $0 baseline|ebpf" >&2
	exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
WORK_DIR=$(mktemp -d /tmp/oakestra-e2e.XXXXXX)
STATE_FILE="$WORK_DIR/state.json"
BIN="$WORK_DIR/NetManager"
# Results survive the WORK_DIR cleanup below; everything else (logs, sockets,
# per-run configs) is scratch and gets removed.
RESULTS_DIR="$SCRIPT_DIR/results"
mkdir -p "$RESULTS_DIR"

# shellcheck source=lib/topology.sh
source "$SCRIPT_DIR/lib/topology.sh"

MOSQUITTO_PID=""
STUB_PID=""
NODE_A_PID=""
NODE_B_PID=""
CONTAINER_A_PID=""
CONTAINER_B_PID=""

cleanup() {
	echo "--- tearing down ---"
	for pid in "$CONTAINER_A_PID" "$CONTAINER_B_PID" "$NODE_A_PID" "$NODE_B_PID" "$STUB_PID" "$MOSQUITTO_PID"; do
		[[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
	done
	sleep 1
	topology_down
	rm -rf "$WORK_DIR"
}
trap cleanup EXIT

echo "--- building NetManager (native arch, for in-place execution) ---"
(cd "$REPO_ROOT" && go build -o "$BIN" .)

echo "--- topology up ---"
topology_up

echo "--- starting mosquitto on ${BROKER_IP}:1883 ---"
mosquitto -p 1883 -d -v >"$WORK_DIR/mosquitto.log" 2>&1 &
# NOTE: mosquitto's default config binds 0.0.0.0, which is fine here since
# nothing outside this netns topology can reach it. Give it a moment.
sleep 1
MOSQUITTO_PID=$(pgrep -f "mosquitto -p 1883" | head -1)

echo '{"jobs": []}' >"$STATE_FILE"
python3 "$SCRIPT_DIR/lib/mqtt_stub.py" --broker "$BROKER_IP" --state "$STATE_FILE" >"$WORK_DIR/stub.log" 2>&1 &
STUB_PID=$!

write_config() {
	local dir=$1 node_ip=$2 ebpf_enabled=$3
	mkdir -p "$dir"
	cat >"$dir/netcfg.json" <<EOF
{
  "NodePublicAddress": "${node_ip}",
  "NodePublicPort": "50103",
  "ClusterUrl": "${BROKER_IP}",
  "ClusterMqttPort": "1883",
  "DefaultInterface": "",
  "Debug": true,
  "PublicIPNetworking": false,
  "MqttCert": "",
  "MqttKey": "",
  "EbpfEnabled": ${ebpf_enabled}
}
EOF
	cp "$REPO_ROOT/config/tuncfg.json" "$dir/tuncfg.json"
}

EBPF_ENABLED="false"
[[ "$MODE" == "ebpf" ]] && EBPF_ENABLED="true"

write_config "$WORK_DIR/etc-node-a" "$NODE_A_IP" "$EBPF_ENABLED"
write_config "$WORK_DIR/etc-node-b" "$NODE_B_IP" "$EBPF_ENABLED"

# Each node gets its own mount namespace layered on top of the *persistent*
# netns topology_up created, so /etc/netmanager can point at a different
# netcfg.json per node without the two instances stepping on each other.
# NOTE: this is the part most likely to need iteration - `ip netns exec`
# alone does not isolate mounts, hence the nested `unshare --mount`.
start_node() {
	local netns=$1 etc_dir=$2 log=$3
	ip netns exec "$netns" unshare --mount -- sh -c "
		mkdir -p /etc/netmanager
		mount --bind '$etc_dir' /etc/netmanager
		exec '$BIN'
	" >"$log" 2>&1 &
	echo $!
}

echo "--- starting node-net-manager (mode=$MODE) on both nodes ---"
NODE_A_PID=$(start_node "$NODE_A_NETNS" "$WORK_DIR/etc-node-a" "$WORK_DIR/node-a.log")
NODE_B_PID=$(start_node "$NODE_B_NETNS" "$WORK_DIR/etc-node-b" "$WORK_DIR/node-b.log")
sleep 2

register_node() {
	local node_netns=$1 client_id=$2
	ip netns exec "$node_netns" curl -sf -X POST \
		--unix-socket /etc/netmanager/netmanager.sock \
		-d "{\"client_id\":\"${client_id}\",\"cluster_address\":\"${BROKER_IP}\"}" \
		http://localhost/register
}

echo "--- registering both nodes ---"
register_node "$NODE_A_NETNS" node-a
register_node "$NODE_B_NETNS" node-b
sleep 1

echo "--- spawning containers ---"
CONTAINER_A_PID=$(spawn_container "$NODE_A_NETNS")
CONTAINER_B_PID=$(spawn_container "$NODE_B_NETNS")
sleep 1

JOB_NAME="e2eapp.e2ens.e2esvc.e2esvcns"
VIP="10.30.1.1" # shared RoundRobin VIP both instances answer on

deploy_container() {
	local node_netns=$1 pid=$2 instance=$3
	ip netns exec "$node_netns" curl -sf -X POST \
		--unix-socket /etc/netmanager/netmanager.sock \
		-d "{\"pid\":${pid},\"serviceName\":\"${JOB_NAME}\",\"instanceNumber\":${instance},\"portMappings\":\"\"}" \
		http://localhost/container/deploy
}

echo "--- deploying instance 0 on node-a, instance 1 on node-b ---"
RESP_A=$(deploy_container "$NODE_A_NETNS" "$CONTAINER_A_PID" 0)
RESP_B=$(deploy_container "$NODE_B_NETNS" "$CONTAINER_B_PID" 1)
NSIP_A=$(echo "$RESP_A" | python3 -c 'import json,sys; print(json.load(sys.stdin)["nsAddress"])')
NSIP_B=$(echo "$RESP_B" | python3 -c 'import json,sys; print(json.load(sys.stdin)["nsAddress"])')
echo "node-a instance nsip: $NSIP_A"
echo "node-b instance nsip: $NSIP_B"

# Tell the mqtt stub about both instances now that their real nsips are
# known, so table queries from either node resolve the shared VIP to both.
python3 - "$STATE_FILE" "$JOB_NAME" "$VIP" "$NSIP_A" "$NODE_A_IP" "$NSIP_B" "$NODE_B_IP" <<'PYEOF'
import json, sys
state_path, job_name, vip, nsip_a, node_a, nsip_b, node_b = sys.argv[1:8]
def instance(n, nsip, node_ip):
    return {
        "instance_number": n,
        "nsip": nsip,
        "nsipv6": "",
        "node_ip": node_ip,
        "node_port": 50103,
        "service_ip": [
            {"type": "RR", "address": vip, "address_v6": ""},
            {"type": "InstanceNumber", "address": f"10.30.1.{10+n}", "address_v6": ""},
        ],
    }
state = {"jobs": [{"job_name": job_name, "instances": [
    instance(0, nsip_a, node_a),
    instance(1, nsip_b, node_b),
]}]}
with open(state_path, "w") as f:
    json.dump(state, f)
PYEOF

echo "--- refreshing both nodes' service tables ---"
# force each node to (re)run a table query now that the stub knows about
# both instances, rather than waiting for the next natural trigger
ip netns exec "$NODE_A_NETNS" curl -sf --unix-socket /etc/netmanager/netmanager.sock \
	-o /dev/null -w '' "http://localhost/" || true
sleep 2

echo "--- running iperf3 (node-b listens on its InstanceNumber VIP, node-a's container connects via the shared VIP) ---"
CONTAINER_B_NETNS_PID=$CONTAINER_B_PID
CONTAINER_A_NETNS_PID=$CONTAINER_A_PID

nsenter --net="/proc/${CONTAINER_B_NETNS_PID}/ns/net" iperf3 -s -1 -D --pidfile "$WORK_DIR/iperf3.pid"
sleep 1
RESULT_FILE="$RESULTS_DIR/iperf3-${MODE}.json"
nsenter --net="/proc/${CONTAINER_A_NETNS_PID}/ns/net" iperf3 -c "$VIP" -t 10 -J | tee "$RESULT_FILE"

echo "--- results written to $RESULT_FILE ---"
echo "(re-run with the other mode and diff $RESULTS_DIR/iperf3-baseline.json vs iperf3-ebpf.json)"
