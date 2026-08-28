#!/usr/bin/env python3
"""Minimal stand-in for the root/cluster-service-manager control plane,
just enough of it for the M0 e2e harness (../run.sh) to drive two real
node-net-manager instances over MQTT without the Python services or MongoDB.

Speaks the same two request/response pairs node-net-manager's mqtt package
uses (see mqtt/NetworkManagementHandlers.go and mqtt/Tablequery.go):

  nodes/<client_id>/net/subnet             -> nodes/<client_id>/net/subnetwork/result
  nodes/<client_id>/net/tablequery/request -> nodes/<client_id>/net/tablequery/result

The instance list (which job, which VIPs, which node each instance lands
on) is read from a JSON state file that run.sh rewrites after each
/container/deploy call, once the real nsip is known - this stub has no
deployment logic of its own, it only answers queries about state run.sh
already told it about.
"""
import argparse
import json
import sys
import time

import paho.mqtt.client as mqtt

# client_id -> container bridge subnet handed out on "subnet" requests.
# /26 per node matches NewEnvironmentClusterConfigured's default mask.
NODE_SUBNETS = {
    "node-a": {"address": "10.16.1.0", "addressv6": "fd16:1::"},
    "node-b": {"address": "10.16.2.0", "addressv6": "fd16:2::"},
}


def load_state(path):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return {"jobs": []}


def find_job_by_name(state, sname):
    for job in state.get("jobs", []):
        if job["job_name"] == sname:
            return job
    return None


def find_job_by_vip(state, sip):
    for job in state.get("jobs", []):
        for instance in job["instances"]:
            for sipentry in instance["service_ip"]:
                if sipentry["address"] == sip:
                    return job
    return None


def build_response(job):
    return {
        "app_name": job["job_name"],
        "query_key": job["job_name"],
        "instance_list": [
            {
                "instance_number": inst["instance_number"],
                "namespace_ip": inst["nsip"],
                "namespace_ip_v6": inst.get("nsipv6", ""),
                "host_ip": inst["node_ip"],
                "host_port": inst["node_port"],
                "service_ip": [
                    {
                        "IpType": s["type"],
                        "Address": s["address"],
                        "Address_v6": s.get("address_v6", ""),
                    }
                    for s in inst["service_ip"]
                ],
            }
            for inst in job["instances"]
        ],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--broker", default="10.99.0.1")
    parser.add_argument("--port", type=int, default=1883)
    parser.add_argument("--state", required=True, help="path to the JSON state file run.sh maintains")
    args = parser.parse_args()

    def on_connect(client, userdata, flags, rc, properties=None):
        print(f"[mqtt_stub] connected (rc={rc}), subscribing", file=sys.stderr)
        client.subscribe("nodes/+/net/subnet")
        client.subscribe("nodes/+/net/tablequery/request")

    def on_message(client, userdata, msg):
        parts = msg.topic.split("/")
        if len(parts) < 4:
            return
        client_id = parts[1]
        leaf = "/".join(parts[3:])
        state = load_state(args.state)

        if leaf == "subnet":
            subnet = NODE_SUBNETS.get(client_id)
            if subnet is None:
                print(f"[mqtt_stub] unknown client_id {client_id!r} for subnet request", file=sys.stderr)
                return
            client.publish(f"nodes/{client_id}/net/subnetwork/result", json.dumps(subnet))
            print(f"[mqtt_stub] {client_id}: subnet -> {subnet}", file=sys.stderr)
            return

        if leaf == "tablequery/request":
            try:
                req = json.loads(msg.payload)
            except json.JSONDecodeError:
                return
            job = None
            if req.get("sname"):
                job = find_job_by_name(state, req["sname"])
            elif req.get("sip"):
                job = find_job_by_vip(state, req["sip"])
            if job is None:
                print(f"[mqtt_stub] {client_id}: tablequery {req} -> no match yet", file=sys.stderr)
                return
            resp = build_response(job)
            client.publish(f"nodes/{client_id}/net/tablequery/result", json.dumps(resp))
            print(f"[mqtt_stub] {client_id}: tablequery {req} -> {job['job_name']}", file=sys.stderr)

    client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message

    while True:
        try:
            client.connect(args.broker, args.port, keepalive=30)
            break
        except (ConnectionRefusedError, OSError):
            print("[mqtt_stub] broker not up yet, retrying...", file=sys.stderr)
            time.sleep(1)

    client.loop_forever()


if __name__ == "__main__":
    main()
