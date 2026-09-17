import json
import logging
from unittest.mock import MagicMock

import pytest
from oakestra_messaging import Message

from interfaces import workerlink
from interfaces.workerlink import (
    _address_handler,
    _deployment_handler,
    _interest_remove_handler,
    _subnet_handler,
    _tablequery_handler,
    _undeployment_handler,
    notify_service_change,
    publish_subnetwork_result,
    publish_tablequery_result,
)

HANDLER_NAMES = [
    "_deployment_handler",
    "_undeployment_handler",
    "_address_handler",
    "_tablequery_handler",
    "_subnet_handler",
    "_interest_remove_handler",
]


@pytest.fixture
def all_handlers_mocked(monkeypatch):
    """Replace all six dispatch targets with MagicMocks and hand back the dict."""
    mocks = {}
    for name in HANDLER_NAMES:
        mock = MagicMock()
        monkeypatch.setattr(workerlink, name, mock)
        mocks[name] = mock
    return mocks


# --------------------------------------------------------------------------- #
# start()
# --------------------------------------------------------------------------- #


def test_start_subscribes_exactly_six_patterns(bus):
    assert bus.subscriptions == [
        "nodes/+/net/service/deployed",
        "nodes/+/net/service/undeployed",
        "nodes/+/net/service/address-changed",
        "nodes/+/net/tablequery/request",
        "nodes/+/net/subnet",
        "nodes/+/net/interest/remove",
    ]


# --------------------------------------------------------------------------- #
# dispatch
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("topic", "handler_name"),
    [
        ("nodes/n1/net/service/deployed", "_deployment_handler"),
        ("nodes/n1/net/service/undeployed", "_undeployment_handler"),
        ("nodes/n1/net/service/address-changed", "_address_handler"),
        ("nodes/n1/net/tablequery/request", "_tablequery_handler"),
        ("nodes/n1/net/subnet", "_subnet_handler"),
        ("nodes/n1/net/interest/remove", "_interest_remove_handler"),
    ],
)
def test_dispatch_routes_topic_to_handler(bus, all_handlers_mocked, topic, handler_name):
    payload = {"some": "value"}

    bus.deliver(topic, json.dumps(payload))

    all_handlers_mocked[handler_name].assert_called_once_with("n1", payload)
    for name, mock in all_handlers_mocked.items():
        if name != handler_name:
            mock.assert_not_called()


def test_subnetwork_result_echo_not_delivered(bus, all_handlers_mocked):
    # "nodes/+/net/subnet" has one fewer segment than
    # "nodes/n1/net/subnetwork/result", so CSM's own subnetwork/result echo
    # never reaches a handler.
    payload = {"address": "10.19.1.0", "addressv6": "fc00:1::"}

    delivered = bus.deliver("nodes/n1/net/subnetwork/result", json.dumps(payload))

    assert delivered == 0
    for mock in all_handlers_mocked.values():
        mock.assert_not_called()


def test_tablequery_result_echo_runs_no_handler(bus, all_handlers_mocked):
    payload = {"app_name": "a", "instance_list": [], "query_key": "a"}

    bus.deliver("nodes/n1/net/tablequery/result", json.dumps(payload))

    for mock in all_handlers_mocked.values():
        mock.assert_not_called()


def test_main_repo_topics_run_no_handler(bus, all_handlers_mocked):
    # CM/NE's own topics never contain "/net/", so they can't match any of
    # CSM's patterns even though both share one broker.
    for topic in ("nodes/n1/information", "nodes/n1/job", "nodes/n1/jobs/resources"):
        bus.deliver(topic, json.dumps({"anything": "goes"}))

    for mock in all_handlers_mocked.values():
        mock.assert_not_called()


def test_client_id_is_second_segment(bus, all_handlers_mocked):
    bus.deliver("nodes/abc-305/net/interest/remove", json.dumps({"appname": "a"}))

    all_handlers_mocked["_interest_remove_handler"].assert_called_once_with(
        "abc-305", {"appname": "a"}
    )


def test_extra_suffix_not_delivered(bus, all_handlers_mocked):
    # None of the six patterns end in "#", so a trailing path segment doesn't match.
    delivered = bus.deliver(
        "nodes/n1/net/service/deployed/unexpected/suffix", json.dumps({"a": 1})
    )

    assert delivered == 0
    for mock in all_handlers_mocked.values():
        mock.assert_not_called()


def test_malformed_payload_logged_and_next_message_delivered(bus, all_handlers_mocked, caplog):
    with caplog.at_level(logging.ERROR, logger="oakestra_messaging.dispatch"):
        bus.deliver("nodes/n1/net/subnet", "not-json")

    assert any(record.exc_info for record in caplog.records)
    all_handlers_mocked["_subnet_handler"].assert_not_called()

    bus.deliver("nodes/n1/net/subnet", json.dumps({"METHOD": "GET"}))

    all_handlers_mocked["_subnet_handler"].assert_called_once_with(
        "n1", {"METHOD": "GET"}
    )


# --------------------------------------------------------------------------- #
# _deployment_handler
# --------------------------------------------------------------------------- #


def test_deployment_handler_forwards_fields_in_order(monkeypatch):
    recorder = MagicMock()
    monkeypatch.setattr(workerlink, "deployment_status_report", recorder)
    payload = {
        "appname": "app.ns.svc.inst",
        "status": "DEPLOYED",
        "nsip": "10.19.1.2",
        "nsipv6": "fc00::2",
        "instance_number": 0,
        "host_ip": "192.168.1.10",
        "host_port": "50103",
    }

    _deployment_handler("n1", payload)

    recorder.assert_called_once_with(
        "app.ns.svc.inst", "DEPLOYED", "10.19.1.2", "fc00::2", "n1", 0,
        "192.168.1.10", "50103",
    )


def test_deployment_handler_missing_keys_become_none(monkeypatch):
    recorder = MagicMock()
    monkeypatch.setattr(workerlink, "deployment_status_report", recorder)

    _deployment_handler("n1", {})

    recorder.assert_called_once_with(None, None, None, None, "n1", None, None, None)


def test_deployment_handler_swallows_exceptions(monkeypatch):
    monkeypatch.setattr(
        workerlink, "deployment_status_report", MagicMock(side_effect=RuntimeError)
    )

    _deployment_handler("n1", {"appname": "a"})  # must not raise


# --------------------------------------------------------------------------- #
# _undeployment_handler
# --------------------------------------------------------------------------- #


def test_undeployment_handler_is_noop():
    # Still a TODO in production; pins the current no-op so a real
    # implementation is a deliberate test change, not a silent one.
    assert _undeployment_handler("n1", {"appname": "a"}) is None


# --------------------------------------------------------------------------- #
# _address_handler
# --------------------------------------------------------------------------- #


def test_address_handler_forwards_fields(monkeypatch):
    recorder = MagicMock()
    monkeypatch.setattr(workerlink, "deployment_address_update", recorder)
    monkeypatch.setattr(workerlink, "notify_service_change", MagicMock())
    payload = {
        "appname": "app.ns.svc.inst",
        "instance_number": 0,
        "host_ip": "192.168.1.11",
        "host_port": "50103",
    }

    _address_handler("n1", payload)

    recorder.assert_called_once_with(
        "app.ns.svc.inst", "n1", 0, "192.168.1.11", "50103"
    )


def test_address_handler_missing_keys_become_none(monkeypatch):
    recorder = MagicMock()
    monkeypatch.setattr(workerlink, "deployment_address_update", recorder)
    monkeypatch.setattr(workerlink, "notify_service_change", MagicMock())

    _address_handler("n1", {})

    recorder.assert_called_once_with(None, "n1", None, None, None)


def test_address_handler_swallows_exceptions(monkeypatch):
    monkeypatch.setattr(
        workerlink, "deployment_address_update", MagicMock(side_effect=RuntimeError)
    )

    _address_handler("n1", {"appname": "a"})  # must not raise


def test_address_handler_notifies_after_successful_update(monkeypatch):
    monkeypatch.setattr(workerlink, "deployment_address_update", MagicMock())
    notify = MagicMock()
    monkeypatch.setattr(workerlink, "notify_service_change", notify)

    _address_handler("n1", {"appname": "app.ns.svc.inst"})

    notify.assert_called_once_with("app.ns.svc.inst", type="DEPLOYMENT")


def test_address_handler_does_not_notify_when_update_raises(monkeypatch):
    monkeypatch.setattr(
        workerlink, "deployment_address_update", MagicMock(side_effect=RuntimeError)
    )
    notify = MagicMock()
    monkeypatch.setattr(workerlink, "notify_service_change", notify)

    _address_handler("n1", {"appname": "app.ns.svc.inst"})  # must not raise

    notify.assert_not_called()


# --------------------------------------------------------------------------- #
# _interest_remove_handler
# --------------------------------------------------------------------------- #


def test_interest_remove_handler_calls_remove_interest(monkeypatch):
    remove_interest = MagicMock()
    monkeypatch.setattr(workerlink.interests, "remove_interest", remove_interest)

    _interest_remove_handler("n1", {"appname": "app.ns.svc.inst"})

    remove_interest.assert_called_once_with("app.ns.svc.inst", "n1")


def test_interest_remove_handler_missing_appname_passes_none(monkeypatch):
    remove_interest = MagicMock()
    monkeypatch.setattr(workerlink.interests, "remove_interest", remove_interest)

    _interest_remove_handler("n1", {})

    remove_interest.assert_called_once_with(None, "n1")


# --------------------------------------------------------------------------- #
# _tablequery_handler
# --------------------------------------------------------------------------- #


def test_tablequery_handler_sip_takes_precedence_over_sname(monkeypatch):
    add_interest = MagicMock()
    publish = MagicMock()
    monkeypatch.setattr(workerlink.interests, "add_interest", add_interest)
    monkeypatch.setattr(workerlink, "publish_tablequery_result", publish)
    resolution_ip = MagicMock(return_value=("resolved.name", [], []))
    resolution_name = MagicMock()
    monkeypatch.setattr(workerlink.resolution, "service_resolution_ip", resolution_ip)
    monkeypatch.setattr(workerlink.resolution, "service_resolution", resolution_name)

    _tablequery_handler("n1", {"sname": "ignored.name", "sip": "10.30.0.1"})

    resolution_ip.assert_called_once_with("10.30.0.1")
    resolution_name.assert_not_called()
    # query_key is the sip, but app_name is whatever service_resolution_ip
    # resolved: it overwrites the "sname" from the payload.
    add_interest.assert_called_once_with("resolved.name", "n1")
    publish.assert_called_once_with(
        "n1",
        {"app_name": "resolved.name", "instance_list": [], "query_key": "10.30.0.1"},
    )


def test_tablequery_handler_resolution_exception_still_publishes(monkeypatch):
    add_interest = MagicMock()
    publish = MagicMock()
    monkeypatch.setattr(workerlink.interests, "add_interest", add_interest)
    monkeypatch.setattr(workerlink, "publish_tablequery_result", publish)
    monkeypatch.setattr(
        workerlink.resolution,
        "service_resolution_ip",
        MagicMock(side_effect=RuntimeError("db down")),
    )

    _tablequery_handler("n1", {"sname": "app.ns.svc.inst", "sip": "10.30.0.1"})

    # serviceName keeps its pre-exception value (the sname from the payload,
    # never overwritten by the failed unpack), instance_list/siplist stay empty.
    add_interest.assert_called_once_with("app.ns.svc.inst", "n1")
    publish.assert_called_once_with(
        "n1",
        {
            "app_name": "app.ns.svc.inst",
            "instance_list": [],
            "query_key": "10.30.0.1",
        },
    )


def test_tablequery_handler_both_missing_publishes_none_app_name(monkeypatch):
    # Both keys absent (payload.get(...) -> None), not merely empty strings -
    # "" is falsy the same way but stays "" rather than becoming None.
    add_interest = MagicMock()
    publish = MagicMock()
    monkeypatch.setattr(workerlink.interests, "add_interest", add_interest)
    monkeypatch.setattr(workerlink, "publish_tablequery_result", publish)

    _tablequery_handler("n1", {})

    add_interest.assert_called_once_with(None, "n1")
    publish.assert_called_once_with(
        "n1", {"app_name": None, "instance_list": [], "query_key": ""}
    )


def test_tablequery_handler_both_empty_strings_publishes_empty_app_name(monkeypatch):
    # Same code path as above, but "" is never reassigned, so it stays ""
    # instead of becoming None.
    add_interest = MagicMock()
    publish = MagicMock()
    monkeypatch.setattr(workerlink.interests, "add_interest", add_interest)
    monkeypatch.setattr(workerlink, "publish_tablequery_result", publish)

    _tablequery_handler("n1", {"sname": "", "sip": ""})

    add_interest.assert_called_once_with("", "n1")
    publish.assert_called_once_with(
        "n1", {"app_name": "", "instance_list": [], "query_key": ""}
    )


def test_tablequery_handler_publishes_to_result_topic(monkeypatch, bus):
    # Use the real publish_tablequery_result here (not mocked) to check the
    # exact wire topic.
    monkeypatch.setattr(workerlink.interests, "add_interest", MagicMock())
    monkeypatch.setattr(
        workerlink.resolution,
        "service_resolution",
        MagicMock(return_value=([], [])),
    )

    _tablequery_handler("n1", {"sname": "app.ns.svc.inst", "sip": ""})

    expected = {
        "app_name": "app.ns.svc.inst",
        "instance_list": [],
        "query_key": "app.ns.svc.inst",
    }
    assert bus.published[-1] == Message(
        "nodes/n1/net/tablequery/result", json.dumps(expected).encode()
    )


# --------------------------------------------------------------------------- #
# _subnet_handler
# --------------------------------------------------------------------------- #


def test_subnet_handler_get_success(monkeypatch):
    monkeypatch.setattr(
        workerlink,
        "root_service_manager_get_subnet",
        MagicMock(return_value=["10.19.1.0", "fc00:1::"]),
    )
    mongo_update = MagicMock()
    monkeypatch.setattr(
        workerlink, "mongo_find_node_by_id_and_update_subnetwork", mongo_update
    )
    publish = MagicMock()
    monkeypatch.setattr(workerlink, "publish_subnetwork_result", publish)

    _subnet_handler("n1", {"METHOD": "GET"})

    mongo_update.assert_called_once_with("n1", "10.19.1.0", "fc00:1::")
    publish.assert_called_once_with(
        "n1", {"address": "10.19.1.0", "addressv6": "fc00:1::"}
    )


def test_subnet_handler_get_with_none_subnet_skips_mongo_and_publish(monkeypatch):
    monkeypatch.setattr(
        workerlink, "root_service_manager_get_subnet", MagicMock(return_value=None)
    )
    mongo_update = MagicMock()
    publish = MagicMock()
    monkeypatch.setattr(
        workerlink, "mongo_find_node_by_id_and_update_subnetwork", mongo_update
    )
    monkeypatch.setattr(workerlink, "publish_subnetwork_result", publish)

    _subnet_handler("n1", {"METHOD": "GET"})

    mongo_update.assert_not_called()
    publish.assert_not_called()


def test_subnet_handler_get_exception_swallowed(monkeypatch):
    monkeypatch.setattr(
        workerlink,
        "root_service_manager_get_subnet",
        MagicMock(side_effect=RuntimeError("boom")),
    )

    _subnet_handler("n1", {"METHOD": "GET"})  # must not raise


def test_subnet_handler_delete_is_noop(monkeypatch):
    get_subnet = MagicMock()
    monkeypatch.setattr(workerlink, "root_service_manager_get_subnet", get_subnet)

    _subnet_handler("n1", {"METHOD": "DELETE"})

    get_subnet.assert_not_called()


def test_subnet_handler_missing_method_is_noop(monkeypatch):
    get_subnet = MagicMock()
    monkeypatch.setattr(workerlink, "root_service_manager_get_subnet", get_subnet)

    _subnet_handler("n1", {})

    get_subnet.assert_not_called()


# --------------------------------------------------------------------------- #
# publish functions
# --------------------------------------------------------------------------- #


def test_publish_tablequery_result(bus):
    result = {"app_name": "a", "instance_list": [], "query_key": "a"}

    publish_tablequery_result("n1", result)

    assert bus.published[-1] == Message(
        "nodes/n1/net/tablequery/result", json.dumps(result).encode()
    )


def test_publish_subnetwork_result(bus):
    result = {"address": "10.19.1.0", "addressv6": "fc00:1::"}

    publish_subnetwork_result("n1", result)

    assert bus.published[-1] == Message(
        "nodes/n1/net/subnetwork/result", json.dumps(result).encode()
    )


def test_notify_service_change_default_type_is_null(bus):
    notify_service_change("app.ns.svc.inst")

    assert bus.published[-1] == Message(
        "jobs/app.ns.svc.inst/updates_available", json.dumps({"type": None}).encode()
    )


def test_notify_service_change_with_type(bus):
    notify_service_change("app.ns.svc.inst", type="DEPLOYMENT")

    assert bus.published[-1] == Message(
        "jobs/app.ns.svc.inst/updates_available",
        json.dumps({"type": "DEPLOYMENT"}).encode(),
    )


def test_notify_service_change_job_name_can_be_an_ip(bus):
    # `<job>` in jobs/<job>/updates_available may be a service IP string, not a
    # job name. The function has no notion of what a job name is, it just
    # interpolates whatever it's given.
    notify_service_change("10.30.0.1", type="UNDEPLOYMENT")

    assert bus.published[-1] == Message(
        "jobs/10.30.0.1/updates_available",
        json.dumps({"type": "UNDEPLOYMENT"}).encode(),
    )
