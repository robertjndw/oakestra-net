package clusterlink

import (
	"encoding/json"
	"log"
	"net"
	"time"

	messaging "github.com/oakestra/oakestra/libraries/oakestra_messaging_go"
)

var subnetworkResponseChannel chan SubnetworkResponse

// subnetworkTimeout is a variable so tests can shorten it.
var subnetworkTimeout = 10 * time.Second

type SubnetworkResponse struct {
	Address    string `json:"address"`
	Address_v6 string `json:"addressv6"`
}
type subnetworkRequest struct {
	METHOD string `json:"METHOD"`
}
type deployNotification struct {
	Appname        string `json:"appname"`
	Status         string `json:"status"`
	Instancenumber int    `json:"instance_number"`
	Nsip           string `json:"nsip"`
	Nsipv6         string `json:"nsipv6"`
	Hostport       string `json:"host_port"`
	Hostip         string `json:"host_ip"`
}

func handleSubnetworkResult(msg messaging.Message) {
	responseStruct := SubnetworkResponse{}
	if err := json.Unmarshal(msg.Payload, &responseStruct); err != nil {
		log.Println("ERROR - Invalid subnetwork response")
		responseStruct = SubnetworkResponse{}
	}

	// Nil-safe and non-blocking: an unsolicited result (no request in flight,
	// or a race with a fresh RequestSubnetworkBlocking) must not block the
	// bus's shared dispatch path.
	select {
	case subnetworkResponseChannel <- responseStruct:
	default:
		log.Printf("clusterlink: dropped subnetwork/result with no pending request")
	}
}

/*Request a subnetwork to the cluster*/
func RequestSubnetworkBlocking() (SubnetworkResponse, error) {
	subnetworkResponseChannel = make(chan SubnetworkResponse, 1)

	request := subnetworkRequest{METHOD: "GET"}
	jsonreq, _ := json.Marshal(request)
	go func() {
		_ = publish("subnet", string(jsonreq))
	}()

	select {
	case result := <-subnetworkResponseChannel:
		if result.Address != "" || result.Address_v6 != "" {
			return result, nil
		}
	case <-time.After(subnetworkTimeout):
		log.Printf("TIMEOUT - Table query without response, quitting goroutine")
	}

	return SubnetworkResponse{}, net.UnknownNetworkError("Invalid Subnetwork received")
}

func NotifyDeploymentStatus(appname string, status string, instance int, nsip string, nsipv6 string, hostip string, hostport string) error {
	request := deployNotification{
		Appname:        appname,
		Status:         status,
		Instancenumber: instance,
		Nsip:           nsip,
		Nsipv6:         nsipv6,
		Hostip:         hostip,
		Hostport:       hostport,
	}
	jsonreq, _ := json.Marshal(request)
	return publish("service/deployed", string(jsonreq))
}

// NotifyAddressChange notifies the cluster of a node's new address.
func NotifyAddressChange(appname string, instance int, hostip string, hostport string) error {
	request := deployNotification{
		Appname:        appname,
		Instancenumber: instance,
		Hostip:         hostip,
		Hostport:       hostport,
	}
	jsonreq, _ := json.Marshal(request)
	return publish("service/address-changed", string(jsonreq))
}
