package proxy

import (
	"NetManager/env"
	"NetManager/logger"
	"NetManager/network"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"

	"github.com/songgao/water"
)

// create a  new GoProxyTunnel with the configuration from the custom local file
func New() *GoProxyTunnel {
	// load netcfg.json
	cfg, err := os.Open("/etc/netmanager/tuncfg.json")
	if err != nil {
		logger.ErrorLogger().Println(err)
	} else {
		defer cfg.Close()
	}

	defaultconfig := Configuration{
		HostTUNDeviceName:         "goProxyTun",
		TunNetIP:                  "10.19.1.254",
		ProxySubnetwork:           "10.30.0.0",
		ProxySubnetworkMask:       "255.255.0.0",
		TunnelPort:                50103,
		Mtusize:                   1450,
		TunNetIPv6:                "fcef::dead:beef",
		ProxySubnetworkIPv6:       "fc00::",
		ProxySubnetworkIPv6Prefix: 7,
	}

	jsonparser := json.NewDecoder(cfg)
	if err = jsonparser.Decode(&defaultconfig); err != nil {
		logger.ErrorLogger().Println("error parsing tuncfg.json", err)
	}

	logger.InfoLogger().Printf("Utilizing config: %v", defaultconfig)
	return NewCustom(defaultconfig)
}

// create a  new GoProxyTunnel with a custom configuration
func NewCustom(configuration Configuration) *GoProxyTunnel {
	proxy := GoProxyTunnel{
		isListening:      false,
		errorChannel:     make(chan error),
		finishChannel:    make(chan bool),
		stopChannel:      make(chan bool),
		connectionBuffer: make(map[netip.AddrPort]*tunnelConn),
		proxycache:       NewProxyCache(),
		mtusize:          strconv.Itoa(configuration.Mtusize),
	}

	// parse configuration file
	tunconfig := configuration
	proxy.HostTUNDeviceName = tunconfig.HostTUNDeviceName
	proxy.ProxyIPv4Prefix = maskedPrefix(tunconfig.ProxySubnetwork, maskBits(tunconfig.ProxySubnetworkMask))
	proxy.TunnelPort = tunconfig.TunnelPort
	proxy.tunNetIP = tunconfig.TunNetIP

	proxy.ProxyIPv6Prefix = maskedPrefix(tunconfig.ProxySubnetworkIPv6, tunconfig.ProxySubnetworkIPv6Prefix)
	proxy.tunNetIPv6 = tunconfig.TunNetIPv6
	// create the TUN device
	proxy.createTun()

	// set local ip
	ipstring, _ := network.GetLocalIPandIface()
	localAddr, err := netip.ParseAddr(ipstring)
	if err != nil {
		log.Fatalf("Unable to parse the local IP %q: %s", ipstring, err)
	}
	proxy.localIP = localAddr.Unmap()

	proxy.startConnectionEviction()

	logger.InfoLogger().Printf("Created ProxyTun device: %s\n", proxy.ifce.Name())
	logger.InfoLogger().Printf("Local Ip detected: %s\n", proxy.localIP.String())

	return &proxy
}

// maskBits converts a dotted-quad netmask from the config file into a prefix
// length. The config has always expressed the IPv4 proxy subnetwork that way,
// while the IPv6 one is already a prefix length.
func maskBits(dottedMask string) int {
	mask := net.IPMask(net.ParseIP(dottedMask).To4())
	ones, bits := mask.Size()
	if bits == 0 {
		log.Fatalf("Invalid proxy subnetwork mask: %s", dottedMask)
	}
	return ones
}

// maskedPrefix builds the netip.Prefix the datapath tests destination
// addresses against. Masked() normalizes a prefix whose address carries bits
// below the prefix length, which Contains would otherwise reject outright.
func maskedPrefix(address string, bits int) netip.Prefix {
	addr, err := netip.ParseAddr(address)
	if err != nil {
		log.Fatalf("Unable to parse the proxy subnetwork %q: %s", address, err)
	}
	prefix, err := addr.Unmap().Prefix(bits)
	if err != nil {
		log.Fatalf("Invalid proxy subnetwork %s/%d: %s", address, bits, err)
	}
	return prefix
}

func (proxy *GoProxyTunnel) SetEnvironment(env env.EnvironmentManager) {
	proxy.environment = env
}

func (proxy *GoProxyTunnel) IsListening() bool {
	return proxy.isListening
}

// start listening for packets in the TUN Proxy device
func (proxy *GoProxyTunnel) Listen() {
	if !proxy.isListening {
		logger.InfoLogger().Println("Starting proxy listening mode")
		go proxy.tunOutgoingListen()
		go proxy.tunIngoingListen()
	}
}

// create an instance of the proxy TUN device and setup the environment
func (proxy *GoProxyTunnel) createTun() {
	//create tun device
	config := water.Config{
		DeviceType: water.TUN,
	}
	config.Name = proxy.HostTUNDeviceName
	ifce, err := water.New(config)
	if err != nil {
		log.Fatalf("Unable to create new TUN/TAP interface: %s", err)
	}

	logger.InfoLogger().Println("Bringing tun up with addr " + proxy.tunNetIP + "/12")
	cmd := exec.Command("ip", "addr", "add", proxy.tunNetIP+"/12", "dev", ifce.Name())
	logger.InfoLogger().Println()
	err = cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
	logger.InfoLogger().Println("Bringing tun up with IPv6 addr " + proxy.tunNetIPv6 + "/7")
	cmd = exec.Command("ip", "addr", "add", proxy.tunNetIPv6+"/7", "dev", ifce.Name())
	err = cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
	cmd = exec.Command("ip", "link", "set", "dev", ifce.Name(), "up")
	err = cmd.Run()
	if err != nil {
		log.Fatal(err)
	}

	//disabling reverse path filtering
	logger.InfoLogger().Println("Disabling tun dev reverse path filtering")
	cmd = exec.Command("echo", "0", ">", "/proc/sys/net/ipv4/conf/"+ifce.Name()+"/rp_filter")
	err = cmd.Run()
	if err != nil {
		log.Printf("Error disabling tun dev reverse path filtering: %s ", err.Error())
	}

	//Increasing the MTU on the TUN dev
	logger.InfoLogger().Println("Changing TUN's MTU")
	cmd = exec.Command("ip", "link", "set", "dev", ifce.Name(), "mtu", proxy.mtusize)
	err = cmd.Run()
	if err != nil {
		log.Fatal(err.Error())
	}

	//Add network routing rule, Done by default by the system
	logger.InfoLogger().Printf("adding routing rule for %s to %s\n", proxy.ProxyIPv4Prefix.String(), ifce.Name())
	cmd = exec.Command("ip", "route", "add", "10.30.0.0/12", "dev", ifce.Name())
	_, _ = cmd.Output()

	//Add network routing rule, Done by default by the system
	logger.InfoLogger().Printf("adding routing rule for %s to %s\n", proxy.ProxyIPv6Prefix.String(), ifce.Name())
	cmd = exec.Command("ip", "route", "add", proxy.ProxyIPv6Prefix.String(), "dev", ifce.Name())
	_, _ = cmd.Output()

	//add firewalls rules
	logger.InfoLogger().Println("adding firewall rule " + ifce.Name())
	cmd = exec.Command("iptables", "-A", "INPUT", "-i", "tun0", "-m", "state",
		"--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	err = cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
	// IPv6
	cmd = exec.Command("ip6tables", "-A", "INPUT", "-i", "tun0", "-m", "state",
		"--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	err = cmd.Run()
	if err != nil {
		log.Fatal(err)
	}

	// listen to local socket
	lstnAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%v", proxy.TunnelPort))
	if nil != err {
		log.Fatal("Unable to get UDP socket:", err)
	}
	lstnConn, err := net.ListenUDP("udp", lstnAddr)
	if nil != err {
		log.Fatal("Unable to listen on UDP socket:", err)
	}
	err = lstnConn.SetReadBuffer(socketBufferSize)
	if nil != err {
		// Not fatal: the socket still works with whatever the kernel's
		// default/clamped size is, just more prone to drops under bursts.
		logger.ErrorLogger().Println("Unable to grow UDP read buffer:", err)
	}

	proxy.HostTUNDeviceName = ifce.Name()
	proxy.ifce = ifce
	proxy.listenConnection = lstnConn
}

// Configuration implements Stringer interface
func (c *Configuration) String() string {
	return fmt.Sprintf(
		"HostTUNDeviceName: %s\n"+
			"TunnelIP: %s\n"+
			"ProxySubnetwork: %s\n"+
			"ProxySubnetworkMask: %s\n"+
			"TunnelPort: %d\n"+
			"MTUSize: %d\n"+
			"TunNetIPv6: %s\n"+
			"ProxySubnetworkIPv6: %s\n"+
			"ProxySubnetworkIPv6Prefix: %d\n",
		c.HostTUNDeviceName,
		c.TunNetIP,
		c.ProxySubnetwork,
		c.ProxySubnetworkMask,
		c.TunnelPort,
		c.Mtusize,
		c.TunNetIPv6,
		c.ProxySubnetworkIPv6,
		c.ProxySubnetworkIPv6Prefix,
	)
}
