package clusterlink

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	mqttbus "github.com/oakestra/oakestra/libraries/oakestra_messaging_go/mqtt"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"gotest.tools/assert"
)

// brokerFromEnv returns the host/port of a real broker to test against, or
// skips the test if OAKESTRA_TEST_MQTT_ADDR isn't set. Nothing here is
// Mosquitto-specific - any MQTT 3.1.1 broker reachable at that address works.
func brokerFromEnv(t *testing.T) (host, port string) {
	t.Helper()
	addr := os.Getenv("OAKESTRA_TEST_MQTT_ADDR")
	if addr == "" {
		t.Skip("OAKESTRA_TEST_MQTT_ADDR not set; skipping broker-backed integration test")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("invalid OAKESTRA_TEST_MQTT_ADDR %q: %v", addr, err)
	}
	return host, port
}

type receivedMsg struct {
	topic    string
	payload  []byte
	qos      byte
	retained bool
}

// integrationPeer is a real paho client standing in for the cluster service
// manager: subscribed to the node's whole net/ namespace, and able to publish
// results and job update notifications back. It talks paho directly because
// it plays the broker-side peer, not the code under test.
type integrationPeer struct {
	client mqtt.Client

	mu       sync.Mutex
	received []receivedMsg
}

func newPeer(t *testing.T, host, port, nodeID string) *integrationPeer {
	t.Helper()
	p := &integrationPeer{}

	opts := mqtt.NewClientOptions()
	opts.AddBroker(fmt.Sprintf("tcp://%s:%s", host, port))
	opts.SetClientID(fmt.Sprintf("it-peer-%s", nodeID))
	opts.SetDefaultPublishHandler(func(_ mqtt.Client, m mqtt.Message) {
		p.mu.Lock()
		p.received = append(p.received, receivedMsg{
			topic:    m.Topic(),
			payload:  append([]byte(nil), m.Payload()...),
			qos:      m.Qos(),
			retained: m.Retained(),
		})
		p.mu.Unlock()
	})

	subscribed := make(chan struct{})
	opts.OnConnect = func(c mqtt.Client) {
		token := c.Subscribe(fmt.Sprintf("nodes/%s/net/#", nodeID), 1, nil)
		token.Wait()
		close(subscribed)
	}

	p.client = mqtt.NewClient(opts)
	token := p.client.Connect()
	if !token.WaitTimeout(5*time.Second) || token.Error() != nil {
		t.Fatalf("peer failed to connect to the broker: %v", token.Error())
	}
	select {
	case <-subscribed:
	case <-time.After(5 * time.Second):
		t.Fatal("peer timed out waiting for its subscription to be acked")
	}

	t.Cleanup(func() {
		p.client.Disconnect(250)
	})
	return p
}

func (p *integrationPeer) publish(t *testing.T, topic string, qos byte, payload []byte) {
	t.Helper()
	token := p.client.Publish(topic, qos, false, payload)
	if !token.WaitTimeout(5*time.Second) || token.Error() != nil {
		t.Fatalf("peer publish to %s failed: %v", topic, token.Error())
	}
}

func (p *integrationPeer) expect(t *testing.T, topic string, timeout time.Duration) receivedMsg {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		p.mu.Lock()
		for _, m := range p.received {
			if m.topic == topic {
				p.mu.Unlock()
				return m
			}
		}
		p.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for a message on %s", topic)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// startClusterlink brings up a real mqtt bus against the broker under test
// and wires it through Init. Init's Connect blocks until the broker has acked
// the initial subscriptions (tablequery/result, subnetwork/result), so there's
// no separate "ready" signal to wait for.
func startClusterlink(t *testing.T, host, port, nodeID string) *mqttbus.Bus {
	t.Helper()
	resetForTest(t)

	bus, err := mqttbus.NewBus(mqttbus.Config{
		BrokerURL:  host,
		BrokerPort: port,
		ClientID:   nodeID,
		QoS:        1,
	})
	if err != nil {
		t.Fatalf("building the mqtt bus: %v", err)
	}
	if err := Init(bus, nodeID); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() {
		_ = bus.Close()
	})
	return bus
}

func TestIntegration_TableQuery_RoundTrip(t *testing.T) {
	host, port := brokerFromEnv(t)
	nodeID := fmt.Sprintf("it-%d", time.Now().UnixNano())
	startClusterlink(t, host, port, nodeID)
	peer := newPeer(t, host, port, nodeID)
	cache := GetTableQueryRequestCacheInstance()
	tableQueryTimeout = 5 * time.Second

	fixture := loadContract(t, "tablequery_result.json")

	done := make(chan struct{})
	var resp TableQueryResponse
	var qerr error
	go func() {
		resp, qerr = cache.TableQueryByIpRequestBlocking("10.30.0.1")
		close(done)
	}()

	msg := peer.expect(t, fmt.Sprintf("nodes/%s/net/tablequery/request", nodeID), 5*time.Second)
	assert.Equal(t, msg.qos, byte(1))
	assertJSONEqual(t, loadContract(t, "tablequery_request_by_sip.json"), msg.payload)

	peer.publish(t, fmt.Sprintf("nodes/%s/net/tablequery/result", nodeID), 1, fixture)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the table query to resolve")
	}
	assert.NilError(t, qerr)
	var want TableQueryResponse
	assert.NilError(t, json.Unmarshal(fixture, &want))
	assert.DeepEqual(t, resp, want)

	// handleTableQueryResult keeps walking the fixture's other query keys
	// after releasing our waiter, touching the shared cache. Poll until they
	// all show up (nil, nothing else is waiting on them) before the next
	// test resets that cache - a fixed sleep isn't reliable under heavy
	// scheduler/log contention.
	otherKeys := []string{"app.ns.svc.inst", "10.30.0.1", "fdff:1000::1", "10.30.1.1", "fdff:1001::1"}
	deadline := time.Now().Add(5 * time.Second)
	for {
		cache.requestadd.RLock()
		allSeen := true
		for _, key := range otherKeys {
			if _, ok := cache.siprequests[key]; !ok {
				allSeen = false
				break
			}
		}
		cache.requestadd.RUnlock()
		if allSeen {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for handleTableQueryResult to finish walking all query keys")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestIntegration_TableQuery_TimeoutOnTheWire(t *testing.T) {
	host, port := brokerFromEnv(t)
	nodeID := fmt.Sprintf("it-%d", time.Now().UnixNano())
	startClusterlink(t, host, port, nodeID)
	cache := GetTableQueryRequestCacheInstance()
	tableQueryTimeout = 300 * time.Millisecond

	_, err := cache.TableQueryByIpRequestBlocking("10.40.0.1")
	var unknownErr net.UnknownNetworkError
	if !errors.As(err, &unknownErr) {
		t.Fatalf("expected net.UnknownNetworkError, got %T: %v", err, err)
	}
}

func TestIntegration_Subnet_RoundTrip(t *testing.T) {
	host, port := brokerFromEnv(t)
	nodeID := fmt.Sprintf("it-%d", time.Now().UnixNano())
	startClusterlink(t, host, port, nodeID)
	peer := newPeer(t, host, port, nodeID)
	subnetworkTimeout = 5 * time.Second

	done := make(chan struct{})
	var resp SubnetworkResponse
	var rerr error
	go func() {
		resp, rerr = RequestSubnetworkBlocking()
		close(done)
	}()

	msg := peer.expect(t, fmt.Sprintf("nodes/%s/net/subnet", nodeID), 5*time.Second)
	assert.Equal(t, msg.qos, byte(1))
	assertJSONEqual(t, loadContract(t, "subnet_request.json"), msg.payload)

	fixture := loadContract(t, "subnetwork_result.json")
	peer.publish(t, fmt.Sprintf("nodes/%s/net/subnetwork/result", nodeID), 1, fixture)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the subnet request to resolve")
	}
	assert.NilError(t, rerr)
	var want SubnetworkResponse
	assert.NilError(t, json.Unmarshal(fixture, &want))
	assert.DeepEqual(t, resp, want)
}

func TestIntegration_NotifyDeploymentStatus_OnTheWire(t *testing.T) {
	host, port := brokerFromEnv(t)
	nodeID := fmt.Sprintf("it-%d", time.Now().UnixNano())
	startClusterlink(t, host, port, nodeID)
	peer := newPeer(t, host, port, nodeID)

	err := NotifyDeploymentStatus("app.ns.svc.inst", "DEPLOYED", 0, "10.19.1.2", "fc00::2", "192.168.1.10", "50103")
	assert.NilError(t, err)

	msg := peer.expect(t, fmt.Sprintf("nodes/%s/net/service/deployed", nodeID), 5*time.Second)
	assert.Equal(t, msg.qos, byte(1))
	assertJSONEqual(t, loadContract(t, "service_deployed.json"), msg.payload)
}

func TestIntegration_NotifyAddressChange_OnTheWire(t *testing.T) {
	host, port := brokerFromEnv(t)
	nodeID := fmt.Sprintf("it-%d", time.Now().UnixNano())
	startClusterlink(t, host, port, nodeID)
	peer := newPeer(t, host, port, nodeID)

	err := NotifyAddressChange("app.ns.svc.inst", 0, "192.168.1.11", "50103")
	assert.NilError(t, err)

	msg := peer.expect(t, fmt.Sprintf("nodes/%s/net/service/address-changed", nodeID), 5*time.Second)
	assert.Equal(t, msg.qos, byte(1))
	assertJSONEqual(t, loadContract(t, "service_address_changed.json"), msg.payload)
}

func TestIntegration_InterestRegister_UpdatesAvailableTriggersRefresh(t *testing.T) {
	host, port := brokerFromEnv(t)
	nodeID := fmt.Sprintf("it-%d", time.Now().UnixNano())
	startClusterlink(t, host, port, nodeID)
	peer := newPeer(t, host, port, nodeID)
	selfDestructTimeout = 3 * time.Second

	job := fmt.Sprintf("it-job-%d", time.Now().UnixNano())
	env := newFakeEnv()

	RegisterInterest(job, env)
	// Subscribe returns once the broker acks the SUBACK; give it a beat to
	// actually start routing before we publish.
	time.Sleep(200 * time.Millisecond)

	peer.publish(t, fmt.Sprintf("jobs/%s/updates_available", job), 1, loadContract(t, "updates_available.json"))

	deadline := time.Now().Add(5 * time.Second)
	for {
		refreshed := env.Refreshed()
		if len(refreshed) == 1 && refreshed[0] == job {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for RefreshServiceTable(%q), got %v", job, refreshed)
		}
		time.Sleep(10 * time.Millisecond)
	}

	waitForInterestCleared(t, job, 5*time.Second)
}

func TestIntegration_SelfDestruct_PublishesInterestRemoveOnWireAndStopsRefresh(t *testing.T) {
	host, port := brokerFromEnv(t)
	nodeID := fmt.Sprintf("it-%d", time.Now().UnixNano())
	startClusterlink(t, host, port, nodeID)
	peer := newPeer(t, host, port, nodeID)
	selfDestructTimeout = 300 * time.Millisecond

	job := fmt.Sprintf("it-job-%d", time.Now().UnixNano())
	env := newFakeEnv()
	env.setDeployed(job, false)

	RegisterInterest(job, env)

	msg := peer.expect(t, fmt.Sprintf("nodes/%s/net/interest/remove", nodeID), 5*time.Second)
	assert.Equal(t, msg.qos, byte(1))
	var got struct {
		Appname string `json:"appname"`
	}
	assert.NilError(t, json.Unmarshal(msg.payload, &got))
	assert.Equal(t, got.Appname, job)

	waitForInterestCleared(t, job, 5*time.Second)

	// The topic was unsubscribed both at the broker and in the dispatcher's
	// registry: a further updates_available publish must not trigger a refresh.
	peer.publish(t, fmt.Sprintf("jobs/%s/updates_available", job), 1, loadContract(t, "updates_available.json"))
	time.Sleep(300 * time.Millisecond)
	if len(env.Refreshed()) != 0 {
		t.Fatalf("expected no refresh after self-destruct unsubscribed, got %v", env.Refreshed())
	}
}
