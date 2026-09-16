package mqtt

import (
	"NetManager/utils"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"gotest.tools/assert"
)

// resetForTest restores every package-level singleton and seam this package
// exposes so tests can run in any order without leaking state into each
// other. It mirrors what a fresh process start would look like.
func resetForTest(t *testing.T) {
	t.Helper()

	prevNewClient := newClient
	prevTableQueryTimeout := tableQueryTimeout
	prevSubnetworkTimeout := subnetworkTimeout
	prevSelfDestructTimeout := selfDestructTimeout

	initMqttClient = sync.Once{}
	netMqttClient = NetMqttClient{}
	once = sync.Once{}
	tableQueryRequestCacheInstance = TableQueryRequestCache{}
	runningHandlers = utils.NewStringSlice()
	subnetworkResponseChannel = nil

	t.Cleanup(func() {
		if netMqttClient.mainMqttClient != nil {
			netMqttClient.mainMqttClient.Disconnect(0)
		}
		newClient = prevNewClient
		tableQueryTimeout = prevTableQueryTimeout
		subnetworkTimeout = prevSubnetworkTimeout
		selfDestructTimeout = prevSelfDestructTimeout
	})
}

// installFakeClient points the newClient seam at a fake paho client so the
// next InitNetMqttClient call wires up against it instead of a real broker.
// connectErr is returned by the fake's Connect() token.
func installFakeClient(connectErr error) {
	newClient = func(opts *mqtt.ClientOptions) mqtt.Client {
		return newFakeClient(opts, connectErr)
	}
}

// awaitPublish polls the fake client's recorded publishes until one matches
// topic, then waits for that call's token to settle (see fakeToken) before
// returning, so callers can safely tear down shared state right after. It
// fails the test if either wait exceeds timeout.
func awaitPublish(t *testing.T, fc *fakeClient, topic string, timeout time.Duration) publishCall {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		for _, p := range fc.Publishes() {
			if p.topic == topic {
				select {
				case <-p.token.settled:
				case <-time.After(timeout):
					t.Fatalf("timed out waiting for the publish to topic %q to settle", topic)
				}
				return p
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for a publish to topic %q", topic)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// loadContract reads a fixture from the shared testdata/mqtt_contract directory.
func loadContract(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "mqtt_contract", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading contract fixture %s: %v", path, err)
	}
	return data
}

// assertJSONEqual compares two JSON payloads semantically (parsed, not byte-for-byte).
func assertJSONEqual(t *testing.T, want, got []byte) {
	t.Helper()
	var wantAny, gotAny any
	if err := json.Unmarshal(want, &wantAny); err != nil {
		t.Fatalf("unmarshaling expected JSON: %v", err)
	}
	if err := json.Unmarshal(got, &gotAny); err != nil {
		t.Fatalf("unmarshaling actual JSON: %v", err)
	}
	assert.DeepEqual(t, wantAny, gotAny)
}

// writeTestCertPair writes a throwaway self-signed ECDSA cert/key pair into
// t.TempDir() and returns their paths, for exercising tls.LoadX509KeyPair.
func writeTestCertPair(t *testing.T) (certPath, keyPath string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "netmanager-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("creating test certificate: %v", err)
	}

	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	certOut, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("creating cert file: %v", err)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("encoding cert: %v", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshaling test key: %v", err)
	}
	keyOut, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("creating key file: %v", err)
	}
	defer keyOut.Close()
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		t.Fatalf("encoding key: %v", err)
	}

	return certPath, keyPath
}
