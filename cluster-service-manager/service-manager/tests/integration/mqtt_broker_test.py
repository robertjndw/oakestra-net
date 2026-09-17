from unittest.mock import MagicMock

import pytest

from interfaces import workerlink

pytestmark = pytest.mark.integration


def test_tablequery_by_sip_publishes_result(csm_bus, peer, node_id, monkeypatch, contract):
    monkeypatch.setattr(workerlink.interests, "add_interest", MagicMock())
    monkeypatch.setattr(
        workerlink.resolution,
        "service_resolution_ip",
        MagicMock(return_value=("app.ns.svc.inst", [], [])),
    )
    request = contract("tablequery_request_by_sip")

    peer.publish_json(f"nodes/{node_id}/net/tablequery/request", request, qos=1)

    payload, qos = peer.wait_for(f"nodes/{node_id}/net/tablequery/result")
    assert qos == 1
    assert payload == {
        "app_name": "app.ns.svc.inst",
        "instance_list": [],
        "query_key": request["sip"],
    }


def test_subnet_get_publishes_result_and_updates_mongo(
    csm_bus, peer, node_id, monkeypatch, contract
):
    monkeypatch.setattr(
        workerlink,
        "root_service_manager_get_subnet",
        MagicMock(return_value=["10.19.1.0", "fc00:1::"]),
    )
    mongo_update = MagicMock()
    monkeypatch.setattr(
        workerlink, "mongo_find_node_by_id_and_update_subnetwork", mongo_update
    )

    peer.publish_json(f"nodes/{node_id}/net/subnet", contract("subnet_request"), qos=1)

    payload, qos = peer.wait_for(f"nodes/{node_id}/net/subnetwork/result")
    assert qos == 1
    assert payload == {"address": "10.19.1.0", "addressv6": "fc00:1::"}
    mongo_update.assert_called_once_with(node_id, "10.19.1.0", "fc00:1::")


def test_service_deployed_forwards_to_deployment_status_report(
    csm_bus, peer, node_id, monkeypatch, contract, wait_until
):
    recorder = MagicMock()
    monkeypatch.setattr(workerlink, "deployment_status_report", recorder)
    payload = contract("service_deployed")

    peer.publish_json(f"nodes/{node_id}/net/service/deployed", payload, qos=1)

    assert wait_until(lambda: recorder.called)
    recorder.assert_called_once_with(
        payload["appname"],
        payload["status"],
        payload["nsip"],
        payload["nsipv6"],
        node_id,
        payload["instance_number"],
        payload["host_ip"],
        payload["host_port"],
    )


def test_address_changed_forwards_to_deployment_address_update(
    csm_bus, peer, node_id, monkeypatch, contract, wait_until
):
    recorder = MagicMock()
    monkeypatch.setattr(workerlink, "deployment_address_update", recorder)
    monkeypatch.setattr(workerlink, "notify_service_change", MagicMock())
    payload = contract("service_address_changed")

    peer.publish_json(f"nodes/{node_id}/net/service/address-changed", payload, qos=1)

    assert wait_until(lambda: recorder.called)
    recorder.assert_called_once_with(
        payload["appname"],
        node_id,
        payload["instance_number"],
        payload["host_ip"],
        payload["host_port"],
    )


def test_interest_remove_forwards_to_remove_interest(
    csm_bus, peer, node_id, contract, monkeypatch, wait_until
):
    recorder = MagicMock()
    monkeypatch.setattr(workerlink.interests, "remove_interest", recorder)
    payload = contract("interest_remove")

    peer.publish_json(f"nodes/{node_id}/net/interest/remove", payload, qos=1)

    assert wait_until(lambda: recorder.called)
    recorder.assert_called_once_with(payload["appname"], node_id)


def test_notify_service_change_publishes_updates_available(csm_bus, peer, node_id):
    job_name = f"job-{node_id}"
    peer.subscribe(f"jobs/{job_name}/updates_available", qos=1)

    workerlink.notify_service_change(job_name, type="DEPLOYMENT")

    payload, qos = peer.wait_for(f"jobs/{job_name}/updates_available")
    assert qos == 1
    assert payload == {"type": "DEPLOYMENT"}


def test_own_result_publishes_are_not_delivered(
    csm_bus, peer, node_id, monkeypatch, wait_until
):
    # start()'s patterns are exact segment matches: "nodes/+/net/subnet" has
    # one fewer segment than "nodes/<id>/net/subnetwork/result", so the
    # broker's echo of CSM's own subnetwork/result publish never reaches
    # _subnet_handler.
    monkeypatch.setattr(
        workerlink,
        "root_service_manager_get_subnet",
        MagicMock(return_value=["10.19.1.0", "fc00:1::"]),
    )
    monkeypatch.setattr(
        workerlink, "mongo_find_node_by_id_and_update_subnetwork", MagicMock()
    )
    original_subnet_handler = workerlink._subnet_handler
    calls = []

    def spy(client_id, payload):
        calls.append(payload)
        return original_subnet_handler(client_id, payload)

    monkeypatch.setattr(workerlink, "_subnet_handler", spy)

    peer.publish_json(f"nodes/{node_id}/net/subnet", {"METHOD": "GET"}, qos=1)

    payload, qos = peer.wait_for(f"nodes/{node_id}/net/subnetwork/result")
    assert qos == 1

    # Give a wrongly-delivered echo a chance to show up before asserting it
    # never does.
    wait_until(lambda: False, timeout=0.5)
    assert calls == [{"METHOD": "GET"}]


def test_main_repo_topics_are_not_delivered(csm_bus, peer, node_id, monkeypatch, wait_until):
    # CSM subscribes to exactly six "nodes/+/net/..." patterns. A CM/NE-namespace
    # topic has no "/net/" segment, so the broker never routes it to CSM at all
    # and none of the six handlers run.
    handler_names = [
        "_deployment_handler",
        "_undeployment_handler",
        "_address_handler",
        "_tablequery_handler",
        "_subnet_handler",
        "_interest_remove_handler",
    ]
    # Plain mocks, not wraps=: we only care whether each handler fired, not
    # about exercising its real body (which would need its own collaborators
    # mocked too).
    spies = {name: MagicMock() for name in handler_names}
    for name, spy in spies.items():
        monkeypatch.setattr(workerlink, name, spy)

    peer.publish_json(f"nodes/{node_id}/job", {"sname": "x", "status": "RUNNING"}, qos=1)

    # Sentinel on a topic CSM does subscribe to: once its handler has fired,
    # we know the broker has had every chance to deliver (or, correctly,
    # not deliver) the nodes/<id>/job message above.
    peer.publish_json(f"nodes/{node_id}/net/interest/remove", {"appname": "sentinel"}, qos=1)
    assert wait_until(lambda: spies["_interest_remove_handler"].called)

    for name, spy in spies.items():
        if name != "_interest_remove_handler":
            spy.assert_not_called()


def test_malformed_payload_does_not_stop_intake(csm_bus, peer, node_id, monkeypatch, wait_until):
    # The library's Dispatcher catches and logs a handler exception (including
    # a json.loads() failure in workerlink's own `_on_*` wrapper) instead of
    # letting it escape into paho's network thread. Same failure mode that
    # used to hit cluster_manager under paho 1.6.1.
    handler = MagicMock()
    monkeypatch.setattr(workerlink, "_subnet_handler", handler)

    peer.publish_raw(f"nodes/{node_id}/net/subnet", "not-json", qos=1)
    peer.publish_json(f"nodes/{node_id}/net/subnet", {"METHOD": "GET"}, qos=1)

    assert wait_until(lambda: handler.called, timeout=2)
    handler.assert_called_once_with(node_id, {"METHOD": "GET"})
