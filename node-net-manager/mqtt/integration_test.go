package mqtt

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"gotest.tools/assert"
)

// brokerFromEnv returns the host/port of a real broker to test against, or
// skips the test if OAKESTRA_TEST_MQTT_ADDR isn't set. Nothing in this file is
// Mosquitto-specific: any MQTT 3.1.1 broker reachable at that address works,
// which is what lets step 3 of the NATS migration re-point this at NATS's MQTT
// compatibility mode without touching the tests themselves.
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
// results and job update notifications back.
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

// instrumentedToken wraps a real paho Token and closes settled the moment
// Wait/WaitTimeout is actually invoked on it - i.e. once whatever production
// code called Publish has moved past that call in its own program order. See
// instrumentedClient for why this matters.
type instrumentedToken struct {
	mqtt.Token
	settled chan struct{}
	once    sync.Once
}

func wrapToken(inner mqtt.Token) *instrumentedToken {
	return &instrumentedToken{Token: inner, settled: make(chan struct{})}
}

func (t *instrumentedToken) markSettled() { t.once.Do(func() { close(t.settled) }) }
func (t *instrumentedToken) Wait() bool {
	r := t.Token.Wait()
	t.markSettled()
	return r
}
func (t *instrumentedToken) WaitTimeout(d time.Duration) bool {
	r := t.Token.WaitTimeout(d)
	t.markSettled()
	return r
}

// instrumentedClient wraps the real paho client so tests can wait for a
// Publish call to fully finish, including whatever the caller does with the
// token afterwards (PublishToBroker calls Unlock() then WaitTimeout() right
// after Publish() returns). RequestSubnetworkMqttBlocking fires its publish
// from a goroutine it never joins; without this, a test can observe its own
// expected result on the wire and return while that goroutine is still mid
// flight, racing the next test's resetForTest against netMqttClient's fields.
type instrumentedClient struct {
	mqtt.Client

	mu     sync.Mutex
	tokens []*instrumentedToken
}

func (c *instrumentedClient) Publish(topic string, qos byte, retained bool, payload interface{}) mqtt.Token {
	tok := wrapToken(c.Client.Publish(topic, qos, retained, payload))
	c.mu.Lock()
	c.tokens = append(c.tokens, tok)
	c.mu.Unlock()
	return tok
}

// awaitPublishesSettled blocks until every Publish call issued so far has
// settled (see instrumentedToken), i.e. until PublishToBroker has nothing
// left to do with any of them.
func (c *instrumentedClient) awaitPublishesSettled(t *testing.T, timeout time.Duration) {
	t.Helper()
	c.mu.Lock()
	tokens := append([]*instrumentedToken{}, c.tokens...)
	c.mu.Unlock()
	for _, tok := range tokens {
		select {
		case <-tok.settled:
		case <-time.After(timeout):
			t.Fatal("timed out waiting for a publish to settle")
		}
	}
}

// startNetManagerClient brings up a real NetManager mqtt client against the
// broker under test, wrapping newClient to chain onto the real OnConnect
// handler so the caller knows the default subscriptions (tablequery/result,
// subnetwork/result) are live before it proceeds. The returned client lets
// tests wait out fire-and-forget publishes before finishing (see
// instrumentedClient).
func startNetManagerClient(t *testing.T, host, port, nodeID string) *instrumentedClient {
	t.Helper()
	resetForTest(t)

	ready := make(chan struct{})
	var instrumented *instrumentedClient
	newClient = func(opts *mqtt.ClientOptions) mqtt.Client {
		userOnConnect := opts.OnConnect
		opts.OnConnect = func(c mqtt.Client) {
			if userOnConnect != nil {
				userOnConnect(c)
			}
			close(ready)
		}
		instrumented = &instrumentedClient{Client: mqtt.NewClient(opts)}
		return instrumented
	}

	InitNetMqttClient(nodeID, host, port, "", "")

	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the NetManager mqtt client to connect and subscribe")
	}
	return instrumented
}

func TestIntegration_ConnectsWithExactClientID(t *testing.T) {
	host, port := brokerFromEnv(t)
	nodeID := fmt.Sprintf("it-%d", time.Now().UnixNano())
	startNetManagerClient(t, host, port, nodeID)

	client := netMqttClient.mainMqttClient
	if !client.IsConnected() {
		t.Fatal("expected the client to be connected")
	}
	reader := client.OptionsReader()
	assert.Equal(t, reader.ClientID(), nodeID)
}

func TestIntegration_TableQuery_RoundTrip(t *testing.T) {
	host, port := brokerFromEnv(t)
	nodeID := fmt.Sprintf("it-%d", time.Now().UnixNano())
	startNetManagerClient(t, host, port, nodeID)
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

	// TablequeryResultMqttHandler keeps running after it releases our specific
	// waiter: it still walks the fixture's other query keys (app_name, the
	// other service_ip addresses), touching the shared cache. Poll for all of
	// them to show up (mapped to nil, since nothing else is waiting on them)
	// before the next test resets that cache out from under it - a fixed sleep
	// isn't reliable here under heavy scheduler/log contention.
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
			t.Fatal("timed out waiting for TablequeryResultMqttHandler to finish walking all query keys")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestIntegration_TableQuery_TimeoutOnTheWire(t *testing.T) {
	host, port := brokerFromEnv(t)
	nodeID := fmt.Sprintf("it-%d", time.Now().UnixNano())
	startNetManagerClient(t, host, port, nodeID)
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
	client := startNetManagerClient(t, host, port, nodeID)
	peer := newPeer(t, host, port, nodeID)
	subnetworkTimeout = 5 * time.Second

	done := make(chan struct{})
	var resp mqttSubnetworkResponse
	var rerr error
	go func() {
		resp, rerr = RequestSubnetworkMqttBlocking()
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
	var want mqttSubnetworkResponse
	assert.NilError(t, json.Unmarshal(fixture, &want))
	assert.DeepEqual(t, resp, want)

	// RequestSubnetworkMqttBlocking publishes its request from a detached
	// goroutine it never joins; wait for that publish to fully settle (see
	// instrumentedClient) before the next test resets the shared client state
	// out from under it.
	client.awaitPublishesSettled(t, 5*time.Second)
}

func TestIntegration_NotifyDeploymentStatus_OnTheWire(t *testing.T) {
	host, port := brokerFromEnv(t)
	nodeID := fmt.Sprintf("it-%d", time.Now().UnixNano())
	startNetManagerClient(t, host, port, nodeID)
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
	startNetManagerClient(t, host, port, nodeID)
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
	startNetManagerClient(t, host, port, nodeID)
	peer := newPeer(t, host, port, nodeID)
	selfDestructTimeout = 3 * time.Second

	job := fmt.Sprintf("it-job-%d", time.Now().UnixNano())
	env := newFakeEnv()

	MqttRegisterInterest(job, env)
	// RegisterTopic's Subscribe token.WaitTimeout only waits for the SUBACK;
	// give the broker a beat to actually start routing before we publish.
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
	startNetManagerClient(t, host, port, nodeID)
	peer := newPeer(t, host, port, nodeID)
	selfDestructTimeout = 300 * time.Millisecond

	job := fmt.Sprintf("it-job-%d", time.Now().UnixNano())
	env := newFakeEnv()
	env.setDeployed(job, false)

	MqttRegisterInterest(job, env)

	msg := peer.expect(t, fmt.Sprintf("nodes/%s/net/interest/remove", nodeID), 5*time.Second)
	assert.Equal(t, msg.qos, byte(1))
	var got struct {
		Appname string `json:"appname"`
	}
	assert.NilError(t, json.Unmarshal(msg.payload, &got))
	assert.Equal(t, got.Appname, job)

	waitForInterestCleared(t, job, 5*time.Second)

	// The topic was unsubscribed both at the broker and in the dispatcher's
	// topic map: a further updates_available publish must not trigger a refresh.
	peer.publish(t, fmt.Sprintf("jobs/%s/updates_available", job), 1, loadContract(t, "updates_available.json"))
	time.Sleep(300 * time.Millisecond)
	if len(env.Refreshed()) != 0 {
		t.Fatalf("expected no refresh after self-destruct unsubscribed, got %v", env.Refreshed())
	}
}
