# MQTT contract fixtures (oakestra-net)

Golden payloads for the MQTT link between `cluster_service_manager` (CSM,
Python) and `NetManager` (NM, Go). Both suites load these files and compare
them semantically (parsed JSON, not bytes). Change a fixture only together with
both suites: `cluster-service-manager/service-manager/tests/` and
`node-net-manager/mqtt/`.

Node scoped topics are `nodes/<nodeID>/net/...`, where `nodeID` is the worker
id NodeEngine hands to NM over the unix socket `POST /register`. NM uses that
exact string as its MQTT client id (NodeEngine uses `<nodeID>-ne`).

| Fixture | Topic | Producer | Consumer | QoS |
|---|---|---|---|---|
| `tablequery_request_by_sip.json`, `tablequery_request_by_name.json` | `nodes/<id>/net/tablequery/request` | NM `tableQueryRequestBlocking` | CSM `_tablequery_handler` | 1 |
| `tablequery_result.json` | `nodes/<id>/net/tablequery/result` | CSM `mqtt_publish_tablequery_result` | NM `TablequeryResultMqttHandler` | 1 |
| `tablequery_result_csm_shape.json` | same | what CSM actually emits (see notes) | | 1 |
| `subnet_request.json` | `nodes/<id>/net/subnet` | NM `RequestSubnetworkMqttBlocking` | CSM `_subnet_handler` | 1 |
| `subnetwork_result.json` | `nodes/<id>/net/subnetwork/result` | CSM `mqtt_publish_subnetwork_result` | NM `subnetworkAssignmentMqttHandler` | 1 |
| `service_deployed.json` | `nodes/<id>/net/service/deployed` | NM `NotifyDeploymentStatus` | CSM `_deployment_handler` | 1 |
| `service_address_changed.json` | `nodes/<id>/net/service/address-changed` | NM `NotifyAddressChange` | CSM `_address_handler` | 1 |
| `interest_remove.json` | `nodes/<id>/net/interest/remove` | NM `cleanInterestTowardsJob` | CSM `_interest_remove_handler` | 1 |
| `updates_available.json` | `jobs/<job>/updates_available` | CSM `mqtt_notify_service_change` | NM `jobUpdatesTimer.MessageHandler` | 1 |

CSM subscribes to exactly `nodes/+/net/#`. `nodes/<id>/net/service/undeployed`
is matched by a CSM handler that is a no-op, and nothing publishes it.

Notes pinned by the tests:

- `host_port` type mismatch: NM publishes it as a JSON string
  (`mqttDeployNotification.Hostport string`) but parses it as an int in
  `ServiceInstance.HostPort`. CSM stores and echoes whatever it received, so a
  CSM shaped `tablequery/result` (`tablequery_result_csm_shape.json`) fails to
  unmarshal on NM.
- Because of the `#` wildcard the broker delivers CSM's own
  `tablequery/result` and `subnetwork/result` publishes back to CSM. The loose
  regex `^nodes/.*/net/subnet` runs `_subnet_handler` on the echoed
  `subnetwork/result` payload, which has no `METHOD` and is a no-op.
- Timeouts in code differ from the doc comments: table query 5 s (doc says
  10 s), subnet request 10 s, interest self destruct 10 s (doc says 5 min).
- On a table query timeout the in-flight map entry is never removed, so the
  next query for the same key fails with "Table query already happening".
- `<job>` in `jobs/<job>/updates_available` may be a service IP string, not a
  job name.
