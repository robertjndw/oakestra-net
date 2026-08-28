package model

type NetConfiguration struct {
	NodePublicAddress  string
	NodePublicPort     string
	ClusterUrl         string
	ClusterMqttPort    string
	DefaultInterface   string
	Debug              bool
	PublicIPNetworking bool
	MqttCert           string
	MqttKey            string
	// EbpfEnabled toggles the in-kernel TC fast path (see the ebpf package).
	// It is an accelerator on top of ProxyTUN, never a replacement, so
	// leaving it off - or a failed load at startup - just means every
	// packet takes the existing userspace path.
	EbpfEnabled bool
}

var NetConfig NetConfiguration
var WorkerID string
