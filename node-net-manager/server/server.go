package server

import (
	"NetManager/ebpf"
	"NetManager/env"
	"NetManager/handlers"
	"NetManager/logger"
	"NetManager/model"
	"NetManager/mqtt"
	"NetManager/network"
	"NetManager/proxy"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
)

const IP_UPDATE_TIMER = 2 * time.Minute

type undeployRequest struct {
	Servicename    string `json:"serviceName"`
	Instancenumber int    `json:"instanceNumber"`
}

type registerRequest struct {
	ClientID       string `json:"client_id"`
	ClusterAddress string `json:"cluster_address"`
}

type DeployResponse struct {
	ServiceName string `json:"serviceName"`
	NsAddress   string `json:"nsAddress"`
}

func update() {
	for {
		time.Sleep(IP_UPDATE_TIMER)
		defaultLink := network.GetOutboundIP()
		if model.NetConfig.NodePublicAddress != defaultLink.String() {
			logger.InfoLogger().Printf("Updating NodePublicAddress from %s to %s", model.NetConfig.NodePublicAddress, defaultLink.String())
			// update service in the cluster
			//for each service instance in the worker, update the public address
			for _, si := range Env.GetTableEntriesOnNode() {
				err := mqtt.NotifyAddressChange(si.Appname, si.Instancenumber, defaultLink.String(), model.NetConfig.NodePublicPort)
				if err != nil {
					logger.ErrorLogger().Println("[ERROR]:", err)
				}
			}
			model.NetConfig.NodePublicAddress = defaultLink.String()
		}
	}
}

func HandleRequests(port int) {
	netRouter := mux.NewRouter().StrictSlash(true)
	netRouter.HandleFunc("/register", register).Methods("POST")

	//If default route, fetch default gateway address and use that, update regularly
	if model.NetConfig.NodePublicAddress == "0.0.0.0" {
		defaultLink := network.GetOutboundIP()
		model.NetConfig.NodePublicAddress = defaultLink.String()
		go update()
	}

	handlers.RegisterAllManagers(&Env, &model.WorkerID, model.NetConfig.NodePublicAddress, model.NetConfig.NodePublicPort, netRouter)

	if port <= 0 {
		logger.InfoLogger().Println("Starting NetManager on unix socket /etc/netmanager/netmanager.sock")
		_ = os.Remove("/etc/netmanager/netmanager.sock")
		listener, err := net.Listen("unix", "/etc/netmanager/netmanager.sock")
		if err != nil {
			log.Fatalf("Could not create listner: %s", err)
		}
		log.Fatal(http.Serve(listener, netRouter))
	} else {
		log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), netRouter))
	}
}

var (
	Env   env.Environment
	Proxy *proxy.GoProxyTunnel
)

/*
Endpoint: /register
Usage: used to initialize the Network manager. The network manager must know his local subnetwork.
Method: POST
Request Json:

	{
		client_id:string # id of the worker node
	}

Response: 200 or Failure code
*/
func register(writer http.ResponseWriter, request *http.Request) {
	logger.InfoLogger().Println("Received registration request, registering the NetManager to the Cluster")

	reqBody, _ := io.ReadAll(request.Body)
	var requestStruct registerRequest
	err := json.Unmarshal(reqBody, &requestStruct)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	log.Println(requestStruct)

	// drop the request if the node is already initialized
	if model.WorkerID != "" {
		if model.WorkerID == requestStruct.ClientID {
			logger.InfoLogger().Printf("Node already initialized")
			writer.WriteHeader(http.StatusOK)
		} else {
			logger.InfoLogger().Printf("Attempting to re-initialize a node with a different worker ID")
			writer.WriteHeader(http.StatusBadRequest)
		}
		return
	}

	model.WorkerID = requestStruct.ClientID

	//Use default cluster address given by NodeEngine version >= v0.4.302
	if requestStruct.ClusterAddress != "" {
		model.NetConfig.ClusterUrl = requestStruct.ClusterAddress
	}

	//log registration startup
	logger.InfoLogger().Printf(
		"STARTUP_CONFIG: Node=%s:%s | Cluster=%s:%s",
		model.NetConfig.NodePublicAddress,
		model.NetConfig.NodePublicPort,
		model.NetConfig.ClusterUrl,
		model.NetConfig.ClusterMqttPort,
	)

	// initialize mqtt connection to the broker
	mqtt.InitNetMqttClient(requestStruct.ClientID, model.NetConfig.ClusterUrl, model.NetConfig.ClusterMqttPort, model.NetConfig.MqttCert, model.NetConfig.MqttKey)

	// initialize the proxy tunnel
	Proxy = proxy.New()
	Proxy.Listen()

	// initialize the Env Manager
	Env = *env.NewEnvironmentClusterConfigured(Proxy.HostTUNDeviceName)

	Proxy.SetEnvironment(&Env)

	if model.NetConfig.EbpfEnabled {
		loadEbpfFastPath()
	}

	logger.InfoLogger().Printf("NetManager is now running 🟢")
	writer.WriteHeader(http.StatusOK)
}

// loadEbpfFastPath probes the kernel, loads the TC programs from oakestra.c
// and attaches tc_decap to the NIC. Any failure here is logged and left as
// a no-op Env.ebpfManager (nil): every fast-path hook falls through to
// TC_ACT_OK on anything it doesn't recognize, so pure ProxyTUN is always a
// safe fallback - see the ebpf package doc comment.
func loadEbpfFastPath() {
	nicIfindex, err := Env.NicIfindex()
	if err != nil {
		logger.ErrorLogger().Println("ebpf: resolving NIC ifindex, staying on ProxyTUN:", err)
		return
	}

	nodeIP := net.ParseIP(model.NetConfig.NodePublicAddress)
	manager, err := ebpf.Load(nicIfindex, nodeIP, Proxy.TunnelPort)
	if err != nil {
		logger.ErrorLogger().Println("ebpf: load failed, staying on ProxyTUN:", err)
		return
	}

	if err := manager.AttachDecap(); err != nil {
		logger.ErrorLogger().Println("ebpf: attaching tc_decap, staying on ProxyTUN:", err)
		_ = manager.Close()
		return
	}

	// A VIP miss on the fast path re-runs the exact same table-query flow
	// ProxyTunnel.outgoingProxy already uses on a proxycache miss; the
	// result feeds back into the fast path via Environment.AddTableQueryEntry.
	manager.OnVIPMiss = func(vip net.IP) {
		Env.GetTableEntryByServiceIP(vip)
	}

	Env.SetEbpfManager(manager)
}

// Shutdown detaches the eBPF fast path, if it is active, so a restart does
// not find stale TC filters still attached to interfaces that outlive this
// process (veths do, the NIC always does).
func Shutdown() {
	if m := Env.EbpfManager(); m != nil {
		if err := m.Close(); err != nil {
			logger.ErrorLogger().Println("ebpf: closing fast path on shutdown:", err)
		}
	}
}
