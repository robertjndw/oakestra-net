package mqtt

import (
	"errors"
	"sync"
	"testing"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"gotest.tools/assert"
)

func TestInitNetMqttClient_Options(t *testing.T) {
	resetForTest(t)
	installFakeClient(nil)

	InitNetMqttClient("node1", "10.0.0.1", "10003", "", "")

	fc := netMqttClient.mainMqttClient.(*fakeClient)
	reader := fc.OptionsReader()

	assert.Equal(t, reader.ClientID(), "node1")
	servers := reader.Servers()
	assert.Equal(t, len(servers), 1)
	assert.Equal(t, servers[0].String(), "tcp://10.0.0.1:10003")
	assert.Equal(t, reader.Username(), "")
	assert.Equal(t, reader.Password(), "")

	if fc.opts.OnConnect == nil {
		t.Fatal("expected OnConnect handler to be set")
	}
	if fc.opts.OnConnectionLost == nil {
		t.Fatal("expected OnConnectionLost handler to be set")
	}
	if fc.opts.DefaultPublishHandler == nil {
		t.Fatal("expected DefaultPublishHandler to be set")
	}
	if fc.opts.TLSConfig != nil {
		t.Fatal("expected no TLS config without a cert")
	}

	netMqttClient.mqttTopicsMutex.RLock()
	defer netMqttClient.mqttTopicsMutex.RUnlock()
	assert.Equal(t, len(netMqttClient.topics), 2)
	if _, ok := netMqttClient.topics["nodes/node1/net/tablequery/result"]; !ok {
		t.Fatal("missing tablequery/result topic")
	}
	if _, ok := netMqttClient.topics["nodes/node1/net/subnetwork/result"]; !ok {
		t.Fatal("missing subnetwork/result topic")
	}

	if netMqttClient.tableQueryRequestCache != GetTableQueryRequestCacheInstance() {
		t.Fatal("expected tableQueryRequestCache to be the package singleton")
	}
}

func TestInitNetMqttClient_TLS_AddsTlsBrokerAfterTcp(t *testing.T) {
	resetForTest(t)
	installFakeClient(nil)
	certPath, keyPath := writeTestCertPair(t)

	InitNetMqttClient("node1", "host", "1883", certPath, keyPath)

	fc := netMqttClient.mainMqttClient.(*fakeClient)
	optsReader := fc.OptionsReader()
	servers := optsReader.Servers()
	assert.Equal(t, len(servers), 2)
	assert.Equal(t, servers[0].String(), "tcp://host:1883")
	assert.Equal(t, servers[1].String(), "tls://host:1883")

	if fc.opts.TLSConfig == nil {
		t.Fatal("expected TLS config to be set")
	}
	assert.Equal(t, len(fc.opts.TLSConfig.Certificates), 1)
}

func TestInitNetMqttClient_TLS_BadCertStillSetsTlsConfig(t *testing.T) {
	// tls.LoadX509KeyPair failing on a bad path only logs the error; SetTLSConfig
	// still runs with the zero-value certificate, and the tls:// broker is still
	// added.
	resetForTest(t)
	installFakeClient(nil)

	InitNetMqttClient("node1", "host", "1883", "/does/not/exist.crt", "/does/not/exist.key")

	fc := netMqttClient.mainMqttClient.(*fakeClient)
	optsReader := fc.OptionsReader()
	servers := optsReader.Servers()
	assert.Equal(t, len(servers), 2)
	assert.Equal(t, servers[1].String(), "tls://host:1883")

	if fc.opts.TLSConfig == nil {
		t.Fatal("expected TLS config to still be set despite the load error")
	}
	assert.Equal(t, len(fc.opts.TLSConfig.Certificates), 1)
	assert.Equal(t, len(fc.opts.TLSConfig.Certificates[0].Certificate), 0)
}

func TestInitNetMqttClient_IsOnceOnly(t *testing.T) {
	resetForTest(t)
	installFakeClient(nil)

	c1 := InitNetMqttClient("node1", "host", "1883", "", "")
	// Different args on the second call are silently ignored: sync.Once already ran.
	c2 := InitNetMqttClient("node2", "otherhost", "9999", "cert", "key")

	if c1 != c2 {
		t.Fatal("expected both calls to return the same pointer")
	}
	assert.Equal(t, c2.clientID, "node1")

	if GetNetMqttClient() != c1 {
		t.Fatal("expected GetNetMqttClient to return the same pointer")
	}
}

func TestInitNetMqttClient_PanicsWhenConnectFails(t *testing.T) {
	resetForTest(t)
	connectErr := errors.New("boom")
	newClient = func(opts *mqtt.ClientOptions) mqtt.Client {
		return newFakeClient(opts, connectErr)
	}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected InitNetMqttClient to panic when Connect fails")
		}
	}()

	InitNetMqttClient("node1", "host", "1883", "", "")
	t.Fatal("unreachable: InitNetMqttClient should have panicked")
}

func TestGetNetMqttClient_BeforeInit_IsZeroValue(t *testing.T) {
	// Before InitNetMqttClient runs, mainMqttClient is nil. Calling PublishToBroker
	// on this would nil-deref on mqttWriteMutex, so only check the shape here.
	resetForTest(t)

	client := GetNetMqttClient()
	if client.mainMqttClient != nil {
		t.Fatal("expected a nil underlying client before Init")
	}
	if client.mqttWriteMutex != nil {
		t.Fatal("expected a nil write mutex before Init")
	}
}

func TestConnectHandler_SubscribesAllTopicsAtQoS1_WithDispatcher(t *testing.T) {
	resetForTest(t)
	installFakeClient(nil)
	InitNetMqttClient("node1", "host", "1883", "", "")
	fc := netMqttClient.mainMqttClient.(*fakeClient)

	fc.opts.OnConnect(fc)

	calls := fc.SubscribeMultiples()
	assert.Equal(t, len(calls), 1)
	assert.DeepEqual(t, calls[0].filters, map[string]byte{
		"nodes/node1/net/tablequery/result": 1,
		"nodes/node1/net/subnetwork/result": 1,
	})
	if calls[0].callback == nil {
		t.Fatal("expected a dispatcher callback to be passed to SubscribeMultiple")
	}
}

func TestDispatcher_SubstringMatchFiresAllMatching(t *testing.T) {
	resetForTest(t)
	installFakeClient(nil)
	InitNetMqttClient("node1", "host", "1883", "", "")
	fc := netMqttClient.mainMqttClient.(*fakeClient)

	var mu sync.Mutex
	fired := map[string]int{}
	record := func(name string) mqtt.MessageHandler {
		return func(client mqtt.Client, msg mqtt.Message) {
			mu.Lock()
			fired[name]++
			mu.Unlock()
		}
	}

	netMqttClient.mqttTopicsMutex.Lock()
	netMqttClient.topics = map[string]mqtt.MessageHandler{
		"nodes/node1/net/tablequery/result": record("tablequery"),
		"nodes/node1/net/subnetwork/result": record("subnetwork"),
		"jobs/x/updates_available":          record("jobupdates"),
	}
	netMqttClient.mqttTopicsMutex.Unlock()

	fc.opts.OnConnect(fc)
	calls := fc.SubscribeMultiples()
	dispatcher := calls[len(calls)-1].callback

	cases := []struct {
		name  string
		topic string
		want  []string
	}{
		{"exact match", "nodes/node1/net/tablequery/result", []string{"tablequery"}},
		{"key is a suffix of the topic", "prefix/nodes/node1/net/tablequery/result", []string{"tablequery"}},
		{"key is a suffix after extra leading characters", "xnodes/node1/net/tablequery/result", []string{"tablequery"}},
		{"truncated topic does not match", "nodes/node1/net/tablequery/resul", nil},
		{"other node does not match", "nodes/node2/net/tablequery/result", nil},
		{"topic containing both keys fires both", "nodes/node1/net/tablequery/result-nodes/node1/net/subnetwork/result", []string{"tablequery", "subnetwork"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mu.Lock()
			fired = map[string]int{}
			mu.Unlock()

			dispatcher(fc, &fakeMessage{topic: c.topic})

			mu.Lock()
			defer mu.Unlock()
			for _, want := range c.want {
				if fired[want] != 1 {
					t.Fatalf("expected handler %q to fire once for topic %q, fired=%v", want, c.topic, fired)
				}
			}
			if len(c.want) == 0 && len(fired) != 0 {
				t.Fatalf("expected no handler to fire for topic %q, fired=%v", c.topic, fired)
			}
		})
	}
}

func TestPublishToBroker_PrefixesNetNamespaceQoS1NotRetained(t *testing.T) {
	resetForTest(t)
	installFakeClient(nil)
	InitNetMqttClient("node1", "host", "1883", "", "")
	fc := netMqttClient.mainMqttClient.(*fakeClient)

	err := netMqttClient.PublishToBroker("tablequery/request", `{"sname":"","sip":"10.30.0.1"}`)
	assert.NilError(t, err)

	calls := fc.Publishes()
	assert.Equal(t, len(calls), 1)
	assert.Equal(t, calls[0].topic, "nodes/node1/net/tablequery/request")
	assert.Equal(t, calls[0].qos, byte(1))
	assert.Equal(t, calls[0].retained, false)
	assert.Equal(t, calls[0].payload, `{"sname":"","sip":"10.30.0.1"}`)
}

func TestPublishToBroker_ReturnsNilEvenOnTokenError(t *testing.T) {
	// PublishToBroker only logs a publish token error, it never surfaces it to the
	// caller.
	resetForTest(t)
	installFakeClient(nil)
	InitNetMqttClient("node1", "host", "1883", "", "")
	fc := netMqttClient.mainMqttClient.(*fakeClient)
	fc.SetPublishError(errors.New("broker rejected publish"))

	err := netMqttClient.PublishToBroker("subnet", `{"METHOD":"GET"}`)
	assert.NilError(t, err)
	assert.Equal(t, len(fc.Publishes()), 1)
}

func TestRegisterTopic_SubscribesDirectlyAtQoS1AndRecords(t *testing.T) {
	resetForTest(t)
	installFakeClient(nil)
	InitNetMqttClient("node1", "host", "1883", "", "")
	fc := netMqttClient.mainMqttClient.(*fakeClient)

	netMqttClient.RegisterTopic("jobs/app/updates_available", func(mqtt.Client, mqtt.Message) {})

	calls := fc.Subscribes()
	assert.Equal(t, len(calls), 1)
	assert.Equal(t, calls[0].topic, "jobs/app/updates_available")
	assert.Equal(t, calls[0].qos, byte(1))

	netMqttClient.mqttTopicsMutex.RLock()
	_, ok := netMqttClient.topics["jobs/app/updates_available"]
	netMqttClient.mqttTopicsMutex.RUnlock()
	if !ok {
		t.Fatal("expected the topic to be recorded so it survives reconnection")
	}
}

func TestDeRegisterTopic_UnsubscribesAndForgets(t *testing.T) {
	resetForTest(t)
	installFakeClient(nil)
	InitNetMqttClient("node1", "host", "1883", "", "")
	fc := netMqttClient.mainMqttClient.(*fakeClient)

	netMqttClient.RegisterTopic("jobs/app/updates_available", func(mqtt.Client, mqtt.Message) {})
	netMqttClient.DeRegisterTopic("jobs/app/updates_available")

	unsubs := fc.Unsubscribes()
	assert.Equal(t, len(unsubs), 1)
	assert.DeepEqual(t, unsubs[0], []string{"jobs/app/updates_available"})

	netMqttClient.mqttTopicsMutex.RLock()
	_, ok := netMqttClient.topics["jobs/app/updates_available"]
	netMqttClient.mqttTopicsMutex.RUnlock()
	if ok {
		t.Fatal("expected the topic to be forgotten after deregistering")
	}
}
