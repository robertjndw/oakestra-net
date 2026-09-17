import json
import logging
import traceback

from interfaces.mongodb_requests import mongo_find_node_by_id_and_update_subnetwork
from interfaces.root_service_manager_requests import root_service_manager_get_subnet
from network.deployment import deployment_address_update, deployment_status_report
from network.tablequery import interests, resolution
from oakestra_messaging import Message, MessageBus, from_env, mqtt_tls_from_env

logger = logging.getLogger("cluster_service_manager")

_bus: MessageBus | None = None


def bus_from_env() -> MessageBus:
    return from_env(
        qos=1,
        tls=mqtt_tls_from_env("cluster_net", "CLUSTER_SERVICE_KEYFILE_PASSWORD"),
        logger=logger,
    )


def start(bus: MessageBus) -> None:
    global _bus
    _bus = bus
    bus.subscribe("nodes/+/net/service/deployed", _on_deployed)
    bus.subscribe("nodes/+/net/service/undeployed", _on_undeployed)
    bus.subscribe("nodes/+/net/service/address-changed", _on_address_changed)
    bus.subscribe("nodes/+/net/tablequery/request", _on_tablequery_request)
    bus.subscribe("nodes/+/net/subnet", _on_subnet)
    bus.subscribe("nodes/+/net/interest/remove", _on_interest_remove)


def _on_deployed(msg: Message) -> None:
    client_id = msg.topic.split("/")[1]
    payload = json.loads(msg.payload)
    logger.debug("JOB-DEPLOYMENT-UPDATE")
    _deployment_handler(client_id, payload)


def _on_undeployed(msg: Message) -> None:
    client_id = msg.topic.split("/")[1]
    payload = json.loads(msg.payload)
    logger.debug("JOB-UNDEPLOYMENT-UPDATE")
    _undeployment_handler(client_id, payload)


def _on_address_changed(msg: Message) -> None:
    client_id = msg.topic.split("/")[1]
    payload = json.loads(msg.payload)
    logger.debug("JOB-ADDRESS-UPDATE")
    _address_handler(client_id, payload)


def _on_tablequery_request(msg: Message) -> None:
    client_id = msg.topic.split("/")[1]
    payload = json.loads(msg.payload)
    logger.debug("JOB-TABLEQUERY-REQUEST")
    _tablequery_handler(client_id, payload)


def _on_subnet(msg: Message) -> None:
    client_id = msg.topic.split("/")[1]
    payload = json.loads(msg.payload)
    logger.debug("JOB-SUBNET-REQUEST")
    _subnet_handler(client_id, payload)


def _on_interest_remove(msg: Message) -> None:
    client_id = msg.topic.split("/")[1]
    payload = json.loads(msg.payload)
    logger.debug("JOB-INTEREST-REMOVE")
    _interest_remove_handler(client_id, payload)


def _deployment_handler(client_id, payload):
    appname = payload.get("appname")
    status = payload.get("status")
    nsIp = payload.get("nsip")
    nsIPv6 = payload.get("nsipv6")
    instance_number = payload.get("instance_number")
    host_ip = payload.get("host_ip")
    host_port = payload.get("host_port")
    try:
        deployment_status_report(
            appname,
            status,
            nsIp,
            nsIPv6,
            client_id,
            instance_number,
            host_ip,
            host_port,
        )
    except Exception as e:
        traceback.print_exc()
        print(e)


def _undeployment_handler(client_id, payload):
    # TODO
    pass


def _address_handler(client_id, payload):
    appname = payload.get("appname")
    instance_number = payload.get("instance_number")
    host_ip = payload.get("host_ip")
    host_port = payload.get("host_port")
    try:
        deployment_address_update(
            appname,
            client_id,
            instance_number,
            host_ip,
            host_port,
        )
        # only fires once the address update actually landed - if
        # deployment_address_update raised, we're in the except below instead
        notify_service_change(appname, type="DEPLOYMENT")
    except Exception as e:
        traceback.print_exc()
        print(e)


def _interest_remove_handler(client_id, payload):
    appname = payload.get("appname")
    interests.remove_interest(appname, client_id)


def _tablequery_handler(client_id, payload):
    querySname = payload.get("sname")
    serviceName = payload.get("sname")
    sip = payload.get("sip")

    instances = []
    siplist = []
    query_key = ""

    # resolve the query and register interest
    try:
        if sip is not None and sip != "":
            query_key = str(sip)
            serviceName, instances, siplist = resolution.service_resolution_ip(sip)
        elif serviceName is not None and serviceName != "":
            query_key = str(serviceName)
            instances, siplist = resolution.service_resolution(serviceName)
    except Exception as e:
        logger.error(e)
        instances = []
        siplist = []

    interests.add_interest(serviceName, client_id)
    result = {
        "app_name": serviceName,
        "instance_list": resolution.format_instance_response(instances, siplist),
        "query_key": query_key,
    }
    logger.debug("Tablequery Result: ", result)
    publish_tablequery_result(client_id, result)


def _subnet_handler(client_id, payload):
    method = payload.get("METHOD")
    if method == "GET":
        try:
            # associate new subnetwork to the node
            addr = root_service_manager_get_subnet()
            if addr is None:
                logger.error(
                    "Root service manager responded with an invalid subnetwork: "
                    + str(addr)
                )
                return
            mongo_find_node_by_id_and_update_subnetwork(client_id, addr[0], addr[1])
            publish_subnetwork_result(
                client_id, {"address": addr[0], "addressv6": addr[1]}
            )
        except Exception as e:
            logger.error(e)
    elif method == "DELETE":
        # remove subnetwork from node
        pass


def publish_tablequery_result(client_id, result):
    topic = "nodes/" + client_id + "/net/tablequery/result"
    _bus.publish(topic, json.dumps(result))


def publish_subnetwork_result(client_id, result):
    topic = "nodes/" + client_id + "/net/subnetwork/result"
    _bus.publish(topic, json.dumps(result))


def notify_service_change(job_name, type=None):
    topic = "jobs/" + job_name + "/updates_available"
    _bus.publish(topic, json.dumps({"type": type}))
