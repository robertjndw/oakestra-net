package mqtt

import (
	"fmt"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// fakeToken is an already resolved paho Token: Wait/WaitTimeout return
// immediately, Done is pre-closed, err is what Error() reports.
//
// settled closes once Wait/WaitTimeout has actually been called. PublishToBroker
// calls WaitTimeout last, after unlocking mqttWriteMutex, and some callers
// (RequestSubnetworkMqttBlocking) run it in a goroutine they never join.
// Waiting on settled is the only way a test can be sure that goroutine is past
// the mutex before resetForTest touches the client.
type fakeToken struct {
	err     error
	done    chan struct{}
	settled chan struct{}
	once    sync.Once
}

func newFakeToken(err error) *fakeToken {
	t := &fakeToken{err: err, done: make(chan struct{}), settled: make(chan struct{})}
	close(t.done)
	return t
}

func (t *fakeToken) markSettled() { t.once.Do(func() { close(t.settled) }) }

func (t *fakeToken) Wait() bool                       { t.markSettled(); return true }
func (t *fakeToken) WaitTimeout(_ time.Duration) bool { t.markSettled(); return true }
func (t *fakeToken) Done() <-chan struct{}            { return t.done }
func (t *fakeToken) Error() error                     { return t.err }

// fakeMessage is a minimal mqtt.Message used to feed handlers directly in tests.
type fakeMessage struct {
	duplicate bool
	qos       byte
	retained  bool
	topic     string
	messageID uint16
	payload   []byte
	acked     bool
}

func (m *fakeMessage) Duplicate() bool   { return m.duplicate }
func (m *fakeMessage) Qos() byte         { return m.qos }
func (m *fakeMessage) Retained() bool    { return m.retained }
func (m *fakeMessage) Topic() string     { return m.topic }
func (m *fakeMessage) MessageID() uint16 { return m.messageID }
func (m *fakeMessage) Payload() []byte   { return m.payload }
func (m *fakeMessage) Ack()              { m.acked = true }

type publishCall struct {
	topic    string
	qos      byte
	retained bool
	payload  string
	token    *fakeToken
}

type subscribeCall struct {
	topic    string
	qos      byte
	callback mqtt.MessageHandler
}

type subscribeMultipleCall struct {
	filters  map[string]byte
	callback mqtt.MessageHandler
}

// fakeClient embeds a nil mqtt.Client so any method we don't override panics
// instead of silently doing nothing. That tells us production code started
// using a paho feature the fake doesn't model.
type fakeClient struct {
	mqtt.Client

	mu sync.Mutex

	opts *mqtt.ClientOptions

	connectErr error
	connected  bool
	disconnect uint
	publishErr error

	publishes          []publishCall
	subscribes         []subscribeCall
	subscribeMultiples []subscribeMultipleCall
	unsubscribes       [][]string
}

func newFakeClient(opts *mqtt.ClientOptions, connectErr error) *fakeClient {
	return &fakeClient{opts: opts, connectErr: connectErr}
}

func (c *fakeClient) Connect() mqtt.Token {
	c.mu.Lock()
	c.connected = c.connectErr == nil
	c.mu.Unlock()
	return newFakeToken(c.connectErr)
}

func (c *fakeClient) Disconnect(quiesce uint) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connected = false
	c.disconnect = quiesce
}

func (c *fakeClient) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

func (c *fakeClient) Publish(topic string, qos byte, retained bool, payload interface{}) mqtt.Token {
	var s string
	switch p := payload.(type) {
	case string:
		s = p
	case []byte:
		s = string(p)
	default:
		panic(fmt.Sprintf("fakeClient.Publish: unsupported payload type %T", payload))
	}
	c.mu.Lock()
	tok := newFakeToken(c.publishErr)
	c.publishes = append(c.publishes, publishCall{topic: topic, qos: qos, retained: retained, payload: s, token: tok})
	c.mu.Unlock()
	return tok
}

func (c *fakeClient) SetPublishError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.publishErr = err
}

func (c *fakeClient) Subscribe(topic string, qos byte, callback mqtt.MessageHandler) mqtt.Token {
	c.mu.Lock()
	c.subscribes = append(c.subscribes, subscribeCall{topic: topic, qos: qos, callback: callback})
	c.mu.Unlock()
	return newFakeToken(nil)
}

func (c *fakeClient) SubscribeMultiple(filters map[string]byte, callback mqtt.MessageHandler) mqtt.Token {
	cp := make(map[string]byte, len(filters))
	for k, v := range filters {
		cp[k] = v
	}
	c.mu.Lock()
	c.subscribeMultiples = append(c.subscribeMultiples, subscribeMultipleCall{filters: cp, callback: callback})
	c.mu.Unlock()
	return newFakeToken(nil)
}

func (c *fakeClient) Unsubscribe(topics ...string) mqtt.Token {
	c.mu.Lock()
	c.unsubscribes = append(c.unsubscribes, append([]string{}, topics...))
	c.mu.Unlock()
	return newFakeToken(nil)
}

func (c *fakeClient) OptionsReader() mqtt.ClientOptionsReader {
	return mqtt.NewOptionsReader(c.opts)
}

func (c *fakeClient) Publishes() []publishCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]publishCall{}, c.publishes...)
}

func (c *fakeClient) Subscribes() []subscribeCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]subscribeCall{}, c.subscribes...)
}

func (c *fakeClient) SubscribeMultiples() []subscribeMultipleCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]subscribeMultipleCall{}, c.subscribeMultiples...)
}

func (c *fakeClient) Unsubscribes() [][]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]string{}, c.unsubscribes...)
}

// fakeEnv implements jobEnvironmentManagerActions for interest/self-destruct tests.
type fakeEnv struct {
	mu sync.Mutex

	deployed map[string]bool

	refreshed []string
	removed   []string
}

func newFakeEnv() *fakeEnv {
	return &fakeEnv{deployed: make(map[string]bool)}
}

func (e *fakeEnv) RefreshServiceTable(sname string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.refreshed = append(e.refreshed, sname)
}

func (e *fakeEnv) RemoveServiceEntries(sname string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.removed = append(e.removed, sname)
}

func (e *fakeEnv) IsServiceDeployed(fullSnameAndInstance string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.deployed[fullSnameAndInstance]
}

func (e *fakeEnv) setDeployed(name string, deployed bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.deployed[name] = deployed
}

func (e *fakeEnv) Refreshed() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string{}, e.refreshed...)
}

func (e *fakeEnv) Removed() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string{}, e.removed...)
}
