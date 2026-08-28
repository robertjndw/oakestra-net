package env

import (
	"NetManager/TableEntryCache"
	"NetManager/logger"
	"NetManager/model"
	"NetManager/mqtt"
	"NetManager/network"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

const NamespaceAlreadyDeclared string = "namespace already declared"

// ServiceLookup is the result of resolving a Service IP on the packet path.
// Entries is empty on a miss, in which case Resolving is either a channel that
// closes when the in-flight background resolution finishes - so the caller can
// hold the packet and retry instead of losing it - or nil when no resolution
// is running and the packet should just be dropped.
//
// Generation is the translation table generation Entries was read under. A
// cached route tagged with the same generation is still current, so the caller
// can skip revalidating it against every replica.
type ServiceLookup struct {
	Entries    []TableEntryCache.TableEntry
	Generation uint64
	Resolving  <-chan struct{}
}

// The packet-path lookups take netip.Addr rather than net.IP: the parser
// produces netip.Addr straight off the wire, and converting back allocated on
// every translated packet.
type EnvironmentManager interface {
	// GetTableEntryByServiceIP returns the entries for addr, starting
	// background resolution on a miss. Resolution needs a blocking MQTT round
	// trip and must never happen on the packet path - see resolveServiceIPOnce.
	GetTableEntryByServiceIP(addr netip.Addr) ServiceLookup
	GetTableEntryByNsIP(addr netip.Addr) (TableEntryCache.TableEntry, bool)
	GetTableEntryByInstanceIP(ip net.IP) (TableEntryCache.TableEntry, bool)
}

type Configuration struct {
	HostBridgeName             string
	HostBridgeIP               string
	HostBridgeMask             string
	HostBridgeIPv6             string
	HostBridgeIPv6Prefix       string
	HostTunName                string
	ConnectedInternetInterface string
	Mtusize                    int
}

type Environment struct {
	//### Environment management variables
	nodeNetwork       net.IPNet
	nodeNetworkv6     net.IPNet
	nameSpaces        []string
	networkInterfaces []networkInterface
	nextVethNumber    int
	proxyName         string
	config            Configuration
	translationTable  TableEntryCache.TableManager
	// resolveLock guards pendingResolves and failedServiceIPs. Both maps are
	// created lazily so the zero Environment stays usable.
	resolveLock      sync.Mutex
	pendingResolves  map[netip.Addr]chan struct{} // ServiceIP -> closed when its in-flight resolution finishes
	failedServiceIPs map[netip.Addr]time.Time     // ServiceIP -> when resolution last failed
	//### Deployment management variables
	deployedServices     map[string]service // all the deployed services with the ip and ports
	deployedServicesLock sync.RWMutex
	nextContainerIP      net.IP // next address for the next container to be deployed
	nextContainerIPv6    net.IP
	totNextAddr          int // number of addresses currently generated, max 62
	totNextAddrv6        int
	addrCache            []net.IP // Cache used to store the free addresses available for new containers
	addrCachev6          []net.IP
	//### Communication variables
	clusterPort string
	clusterAddr string
	mtusize     int
	// tableQuery performs the blocking table query. Nil selects the real MQTT
	// round trip; tests substitute a stub for it.
	tableQuery func(netip.Addr) ([]TableEntryCache.TableEntry, error)
}

type service struct {
	ip          net.IP
	ipv6        net.IP
	sname       string
	portmapping string
	veth        *netlink.Veth
}

// current network interfaces in the system
type networkInterface struct {
	number                   int
	veth0                    string
	veth0ip                  net.IP
	veth1                    string
	veth1ip                  net.IP
	isConnectedToAnInterface bool
	interfaceNumber          int
	namespace                string
}

// NewCustom environment constructor
func NewCustom(proxyname string, customConfig Configuration) *Environment {
	e := Environment{
		nameSpaces:        make([]string, 0),
		networkInterfaces: make([]networkInterface, 0),
		nextVethNumber:    0,
		proxyName:         proxyname,
		config:            customConfig,
		translationTable:  TableEntryCache.NewTableManager(),
		nextContainerIP:   network.NextIPv4(net.ParseIP(customConfig.HostBridgeIP), 1),
		nextContainerIPv6: network.NextIPv6(net.ParseIP(customConfig.HostBridgeIPv6), 1),
		totNextAddr:       1,
		totNextAddrv6:     1,
		addrCache:         make([]net.IP, 0),
		addrCachev6:       make([]net.IP, 0),
		deployedServices:  make(map[string]service, 0),
		clusterAddr:       os.Getenv("CLUSTER_MANAGER_IP"),
		clusterPort:       os.Getenv("CLUSTER_MANAGER_PORT"),
		mtusize:           customConfig.Mtusize,
	}

	// Get Connected Internet Interface
	if e.config.ConnectedInternetInterface == "" {
		_, e.config.ConnectedInternetInterface = network.GetLocalIPandIface()
		logger.InfoLogger().Println(e.config.ConnectedInternetInterface)

	}

	// create bridge
	logger.InfoLogger().Println("Creation of goProxyBridge")
	if err := e.CreateHostBridge(); err != nil {
		log.Fatal(err)
	}

	// disable reverse path filtering
	logger.InfoLogger().Println("Disabling reverse path filtering")
	network.DisableReversePathFiltering(e.config.HostBridgeName)

	// Enable tun device forwarding
	logger.InfoLogger().Println("Enabling packet forwarding")
	network.EnableForwarding(e.config.HostBridgeName, proxyname)

	// Enable bridge MASQUERADING
	logger.InfoLogger().Println("Enabling packet masquerading")
	network.EnableMasquerading(e.config.HostBridgeIP, e.config.HostBridgeMask, e.config.HostBridgeIPv6, e.config.HostBridgeIPv6Prefix, e.config.HostBridgeName, e.config.ConnectedInternetInterface)

	// update status with current network configuration
	logger.InfoLogger().Println("Reading the current environment configuration")

	return &e
}

// NewEnvironmentClusterConfigured Creates a new environment using the default configuration and asking the cluster for a new subnetwork
func NewEnvironmentClusterConfigured(proxyname string) *Environment {
	logger.InfoLogger().Println("Asking the cluster for a new subnetwork")
	subnetwork_response, err := mqtt.RequestSubnetworkMqttBlocking()
	if err != nil {
		log.Fatal("Invalid subnetwork received. Can't proceed.")
	}
	ipv4_subnet := subnetwork_response.Address
	ipv6_subnet := subnetwork_response.Address_v6

	logger.InfoLogger().Println("Creating with default config")
	mtusize, err := strconv.Atoi(os.Getenv("TUN_MTU_SIZE"))
	if mtusize < 0 || err != nil {
		logger.InfoLogger().Printf("Default to mtusize 1450")
		mtusize = 1450
	}
	config := Configuration{
		HostBridgeName:             "goProxyBridge",
		HostBridgeIP:               network.NextIPv4(net.ParseIP(ipv4_subnet), 1).String(),
		HostBridgeMask:             "/26",
		HostBridgeIPv6:             network.NextIPv6(net.ParseIP(ipv6_subnet), 1).String(),
		HostBridgeIPv6Prefix:       "/120",
		HostTunName:                "goProxyTun",
		ConnectedInternetInterface: "",
		Mtusize:                    mtusize,
	}
	return NewCustom(proxyname, config)
}

func (env *Environment) Destroy() {
	_ = netlink.LinkDel(&netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{
			Name: env.config.HostBridgeName,
		},
	})
}

func (env *Environment) IsServiceDeployed(jobName string) bool {
	env.deployedServicesLock.RLock()
	defer env.deployedServicesLock.RUnlock()
	for _, element := range env.deployedServices {
		if element.sname == jobName {
			return true
		}
	}
	return false
}

// ConfigureDockerNetwork creates a docker network compatible with the enviornment and returns it
func (env *Environment) ConfigureDockerNetwork(containername string) (string, error) {
	return "", errors.New("not yet implemented")
}

// create veth pair and connect one to the host bridge
// returns: bridgeVeth name, free Veth name, Vether interface to the veth pair and eventually an error
func (env *Environment) createVethsPairAndAttachToBridge(sname string, mtu int) (*netlink.Veth, error) {
	// Retrieve current bridge
	logger.DebugLogger().Println("Retrieving current bridge ")
	bridge, err := netlink.LinkByName(env.config.HostBridgeName)
	if err != nil {
		logger.ErrorLogger().Println("Error retrieving current bridge: ", err)
		return nil, err
	}
	logger.DebugLogger().Println("Retrieved current bridge")
	hashedName := network.NameUniqueHash(sname, 4)
	veth1name := fmt.Sprintf("veth%s%s%s", "00", strconv.Itoa(env.nextVethNumber), hashedName)
	veth2name := fmt.Sprintf("veth%s%s%s", "01", strconv.Itoa(env.nextVethNumber), hashedName)
	logger.DebugLogger().Println("creating veth pair: " + veth1name + "@" + veth2name)

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: veth1name,
			MTU:  mtu,
		},
		PeerName: veth2name,
	}
	err = netlink.LinkAdd(veth)
	if err != nil {
		return nil, err
	}

	// add veth1 to the bridge
	err = netlink.LinkSetMaster(veth, bridge)
	if err != nil {
		return nil, err
	}

	// set veth status up
	if err = netlink.LinkSetUp(veth); err != nil {
		return nil, err
	}

	return veth, nil
}

// sets the FORWARD firewall rules for the bridge veth
func (env *Environment) setVethFirewallRules(bridgeVethName string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// iptables -A FORWARD -o goProxyBridge -i veth -j ACCEPT
	cmd := exec.Command("iptables", "-A", "FORWARD", "-o", env.config.HostBridgeName, "-i", bridgeVethName, "-j", "ACCEPT")
	err := cmd.Run()
	if err != nil {
		return err
	}
	cmd = exec.Command("iptables", "-A", "FORWARD", "-i", env.config.HostBridgeName, "-o", bridgeVethName, "-j", "ACCEPT")
	err = cmd.Run()
	if err != nil {
		return err
	}
	return nil
}

// add routes inside the container namespace to forward the traffic using the bridge
func (env *Environment) setContainerRoutes(containerPid int, peerVeth string) error {
	// Add route to bridge
	// sudo nsenter -n -t 5565 ip route add 0.0.0.0/0 via 127.19.x.y dev veth013
	err := env.execInsideNs(containerPid, func() error {
		link, err := netlink.LinkByName(peerVeth)
		if err != nil {
			return err
		}
		dst, err := netlink.ParseIPNet("0.0.0.0/0")
		if err != nil {
			return err
		}
		gw := net.ParseIP(env.config.HostBridgeIP)
		return netlink.RouteAdd(&netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       dst,
			Gw:        gw,
		})
	})
	if err != nil {
		logger.ErrorLogger().Printf("Impossible to setup route inside the netns: %v\n", err)
		return err
	}
	return nil
}

func (env *Environment) setIPv6ContainerRoutes(containerPid int, peerVeth string) error {
	err := env.execInsideNs(containerPid, func() error {
		link, err := netlink.LinkByName(peerVeth)
		if err != nil {
			return err
		}
		dstv6, err := netlink.ParseIPNet("::/0")
		if err != nil {
			return err
		}
		gwv6 := net.ParseIP(env.config.HostBridgeIPv6)
		return netlink.RouteAdd(&netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       dstv6,
			Gw:        gwv6,
		})
	})
	if err != nil {
		logger.ErrorLogger().Printf("Impossible to setup IPv6 route inside the netns: %v\n", err)
		return err
	}
	return nil
}

// setup the address of the network namespace veth
func (env *Environment) addPeerLinkNetwork(nspid int, addr string, vethname string) error {
	netlinkAddr, err := netlink.ParseAddr(addr)
	if err != nil {
		return err
	}
	err = env.execInsideNs(nspid, func() error {
		link, err := netlink.LinkByName(vethname)
		if err != nil {
			return err
		}
		err = netlink.AddrAdd(link, netlinkAddr)
		if err == nil {
			err = netlink.LinkSetUp(link)
		}
		return err
	})
	if err != nil {
		return err
	}
	return err
}

// setup the address of the network namespace veth based on Ns name
func (env *Environment) addPeerLinkNetworkByNsName(NsName string, addr string, vethname string) error {
	netlinkAddr, err := netlink.ParseAddr(addr)
	if err != nil {
		return err
	}
	err = env.execInsideNsByName(NsName, func() error {
		link, err := netlink.LinkByName(vethname)
		if err != nil {
			return err
		}
		err = netlink.AddrAdd(link, netlinkAddr)
		if err == nil {
			err = netlink.LinkSetUp(link)
		}
		return err
	})
	return err
}

// disable Duplicate Address Detection (DAD) for IPv6 interfaces in namespace
// to prevent interface startup delay
func (env *Environment) disableDAD(pid int, vethname string) error {
	err := env.execInsideNs(pid, func() error {
		cmd := exec.Command("sysctl", "-w", "net.ipv6.conf.default.accept_dad=0")
		err := cmd.Run()
		if err != nil {
			return err
		}
		cmd = exec.Command("sysctl", "-w", "net.ipv6.conf."+vethname+".accept_dad=0")
		err = cmd.Run()
		return err
	})
	return err
}

// Execute function inside a namespace
func (env *Environment) execInsideNs(pid int, function func() error) error {
	var containerNs netns.NsHandle

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	stdNetns, err := netns.Get()
	if err == nil {
		defer stdNetns.Close()
		containerNs, err = netns.GetFromPid(pid)
		if err == nil {
			defer netns.Set(stdNetns)
			err = netns.Set(containerNs)
			if err == nil {
				err = function()
			}
		}
	}
	return err
}

// Execute function inside a namespace based on Ns name
func (env *Environment) execInsideNsByName(Nsname string, function func() error) error {
	var containerNs netns.NsHandle

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	stdNetns, err := netns.Get()
	if err == nil {
		defer stdNetns.Close()
		containerNs, err = netns.GetFromName(Nsname)
		if err == nil {
			defer netns.Set(stdNetns)
			err = netns.Set(containerNs)
			if err == nil {
				err = function()
			}
		}
	}
	return err
}

// BookVethNumber Update the veth number to be used for the next veth
func (env *Environment) BookVethNumber() {
	env.nextVethNumber = env.nextVethNumber + 1
}

// CreateHostBridge create host bridge if it has not been created yet, return the current host bridge name or the newly created one
func (env *Environment) CreateHostBridge() error {
	// check current declared bridges
	devices, err := net.Interfaces()
	if err != nil {
		return err
	}

	// is HostBridgeName already created? DESTROY IT
	for _, ifce := range devices {
		if ifce.Name == env.config.HostBridgeName {
			logger.DebugLogger().Println("Removing previous bridge")
			env.Destroy()
		}
	}

	// otherwise create it
	logger.DebugLogger().Printf("Creating new bridge: %s\n", env.config.HostBridgeName)
	createbridgeCmd := exec.Command("ip", "link", "add", "name", env.config.HostBridgeName, "mtu", strconv.Itoa(env.mtusize), "type", "bridge")
	_, err = createbridgeCmd.Output()
	if err != nil {
		return err
	}

	// assign ip to the bridge
	logger.DebugLogger().Println("Assigning IPv4 to the new bridge")
	bridgeIpCmd := exec.Command("ip", "a", "add",
		env.config.HostBridgeIP+env.config.HostBridgeMask, "dev", env.config.HostBridgeName)
	_, err = bridgeIpCmd.Output()
	if err != nil {
		return err
	}

	logger.DebugLogger().Println("Assigning IPv6 to the new bridge")
	bridgeIpv6Cmd := exec.Command("ip", "a", "add",
		env.config.HostBridgeIPv6+env.config.HostBridgeIPv6Prefix, "dev", env.config.HostBridgeName)
	_, err = bridgeIpv6Cmd.Output()
	if err != nil {
		return err
	}

	// bring the bridge up
	logger.DebugLogger().Println("Setting bridge UP")
	bridgeUpCmd := exec.Command("ip", "link", "set", "dev", env.config.HostBridgeName, "up")
	_, err = bridgeUpCmd.Output()
	if err != nil {
		return err
	}

	return nil
}

// GetTableEntriesOnNode performs a search in the local ServiceCache for entries with the NodeIp of this node
func (env *Environment) GetTableEntriesOnNode() []TableEntryCache.TableEntry {
	ip := net.ParseIP(model.NetConfig.NodePublicAddress)
	return env.translationTable.SearchByNodeIp(ip)
}

// negativeResolveCacheTTL bounds how often a repeatedly-missed ServiceIP is
// retried once a resolution attempt has failed. Without it, a sustained
// stream of packets to an unresolvable VIP would kick off a fresh background
// query (and its up-to-5s MQTT round trip) every time the previous one's
// in-flight marker clears.
const negativeResolveCacheTTL = 2 * time.Second

// maxConcurrentResolves bounds how many table queries may be in flight at
// once. Each one blocks up to 5s on an MQTT round trip, so without a cap a
// host scanning the proxy subnetwork - trivially large in the IPv6 range -
// would cost one goroutine and one broker request per distinct destination.
const maxConcurrentResolves = 32

// maxFailedServiceIPs caps the negative cache so the same scan can't grow
// it without bound.
const maxFailedServiceIPs = 1024

// GetTableEntryByServiceIP Given a ServiceIP this method performs a search in the local ServiceCache
// If the entry is not present, resolution is kicked off in the background and this call returns
// the channel that signals its completion - see resolveServiceIPOnce for why this must not block.
func (env *Environment) GetTableEntryByServiceIP(addr netip.Addr) ServiceLookup {
	// If entry already available
	table, generation := env.translationTable.SearchByServiceIP(addr)
	if len(table) > 0 {
		// mark the job as just used, so its MQTT interest doesn't expire
		table[0].Touch()
		return ServiceLookup{Entries: table, Generation: generation}
	}

	// Miss: resolving requires a blocking MQTT round trip (up to ~5s, see
	// mqtt.Tablequery). This is called from the single outgoing-packet
	// goroutine, so doing that inline here would stall every flow on the
	// node, not just this one. Drop this packet and resolve in the
	// background instead; the caller can hang onto it and retry once the
	// returned channel closes, or let a TCP retransmit go through.
	return ServiceLookup{Resolving: env.resolveServiceIPOnce(addr)}
}

// resolveServiceIPOnce starts background resolution for ip and returns a
// channel that is closed once the attempt finishes, so a caller can hold onto
// the packet that triggered it. Returns nil when no attempt is running: a
// recent one already failed (see negativeResolveCacheTTL) or too many are
// already in flight, in which case the caller should drop the packet.
func (env *Environment) resolveServiceIPOnce(key netip.Addr) <-chan struct{} {
	env.resolveLock.Lock()

	if done, ok := env.pendingResolves[key]; ok {
		env.resolveLock.Unlock()
		return done
	}

	if failedAt, ok := env.failedServiceIPs[key]; ok {
		if time.Since(failedAt) < negativeResolveCacheTTL {
			env.resolveLock.Unlock()
			return nil
		}
	}

	if len(env.pendingResolves) >= maxConcurrentResolves {
		env.resolveLock.Unlock()
		return nil
	}

	if env.pendingResolves == nil {
		env.pendingResolves = make(map[netip.Addr]chan struct{})
	}
	done := make(chan struct{})
	env.pendingResolves[key] = done
	env.resolveLock.Unlock()

	go func() {
		err := env.resolveServiceIP(key)

		env.resolveLock.Lock()
		delete(env.pendingResolves, key)
		if err != nil {
			env.rememberFailureLocked(key)
		} else {
			delete(env.failedServiceIPs, key)
		}
		env.resolveLock.Unlock()

		close(done)
	}()

	return done
}

// rememberFailureLocked records a failed resolution, first sweeping expired
// entries and - if every entry is still fresh - dropping the map wholesale
// rather than letting it grow. Worst case that costs a handful of ServiceIPs
// one extra query each.
func (env *Environment) rememberFailureLocked(key netip.Addr) {
	if env.failedServiceIPs == nil {
		env.failedServiceIPs = make(map[netip.Addr]time.Time)
	}

	if len(env.failedServiceIPs) >= maxFailedServiceIPs {
		now := time.Now()
		for k, failedAt := range env.failedServiceIPs {
			if now.Sub(failedAt) >= negativeResolveCacheTTL {
				delete(env.failedServiceIPs, k)
			}
		}
		if len(env.failedServiceIPs) >= maxFailedServiceIPs {
			env.failedServiceIPs = make(map[netip.Addr]time.Time)
		}
	}

	env.failedServiceIPs[key] = time.Now()
}

// resolveServiceIP performs the actual (blocking) table query and populates
// the translation table. Must only ever run off the packet path.
//
// Every path that leaves addr unresolved has to report an error, not just log
// one: resolveServiceIPOnce reads the return value to decide whether to arm
// the negative cache, so returning nil after a failed install would clear it
// and let the very next packet start another MQTT round trip.
func (env *Environment) resolveServiceIP(addr netip.Addr) error {
	entryList, err := env.queryTable(addr)
	if err != nil {
		return err
	}
	if len(entryList) < 1 {
		return fmt.Errorf("table query for %s returned no instances", addr)
	}

	// Everything below has to be checked before the table is touched.
	// ReplaceJobEntries deliberately displaces whatever holds the namespace
	// IPs the new entries claim, so installing a response and only then
	// deciding to reject it would take a working route down with it.
	//
	// A table query answers for exactly one job (see responseParser), so the
	// whole instance list can be installed as one atomic replacement instead
	// of entry by entry - each of which would rebuild the table indexes.
	jobName := entryList[0].JobName
	for i := range entryList {
		if entryList[i].JobName != jobName {
			return fmt.Errorf("table query for %s returned entries for both %s and %s",
				addr, jobName, entryList[i].JobName)
		}
	}

	// A response can be well-formed and still not answer the question that was
	// asked: it resolves a job, not necessarily this address.
	if !resolvesServiceIP(entryList, addr) {
		return fmt.Errorf("table query for %s resolved job %s but not that address", addr, jobName)
	}

	if err := env.translationTable.ReplaceJobEntries(jobName, entryList); err != nil {
		return err
	}

	mqtt.MqttRegisterInterest(jobName, env)
	// register interest for sip as well to avoid querying the address too many times
	mqtt.MqttRegisterInterest(addr.String(), env)
	return nil
}

// resolvesServiceIP reports whether any entry actually advertises addr as one
// of its Service IPs.
func resolvesServiceIP(entries []TableEntryCache.TableEntry, addr netip.Addr) bool {
	for i := range entries {
		for _, sip := range entries[i].ServiceIP {
			if a, ok := TableEntryCache.AddrFromIP(sip.Address); ok && a == addr {
				return true
			}
			if a, ok := TableEntryCache.AddrFromIP(sip.Address_v6); ok && a == addr {
				return true
			}
		}
	}
	return false
}

func (env *Environment) queryTable(addr netip.Addr) ([]TableEntryCache.TableEntry, error) {
	if env.tableQuery != nil {
		return env.tableQuery(addr)
	}
	return tableQueryByIP(addr)
}

// GetTableEntryByInstanceIP Given a ServiceIP this method performs a search in the local ServiceCache
// If the entry is not present a TableQuery is performed and the interest registered
func (env *Environment) GetTableEntryByInstanceIP(ip net.IP) (TableEntryCache.TableEntry, bool) {
	addr, ok := TableEntryCache.AddrFromIP(ip)
	if !ok {
		return TableEntryCache.TableEntry{}, false
	}
	// If entry already available
	table, _ := env.translationTable.SearchByServiceIP(addr)
	if len(table) > 0 {
		for elemindex, elem := range table {
			for _, elemIp := range elem.ServiceIP {
				if elemIp.IpType == TableEntryCache.InstanceNumber &&
					(elemIp.Address.Equal(ip) || elemIp.Address_v6.Equal(ip)) {
					return table[elemindex], true
				}
			}
		}
	}
	return TableEntryCache.TableEntry{}, false
}

// GetTableEntryByNsIP Given a NamespaceIP finds the table entry. This search is local because the networking component MUST have all
// the entries for the local deployed services.
func (env *Environment) GetTableEntryByNsIP(addr netip.Addr) (TableEntryCache.TableEntry, bool) {
	return env.translationTable.SearchByNsIP(addr)
}

// RefreshServiceTable force a table query refresh for a service
func (env *Environment) RefreshServiceTable(jobname string) {
	logger.DebugLogger().Printf("Requested table query refresh for %s", jobname)
	entryList, err := tableQueryByJobName(jobname, true)
	if err != nil {
		return
	}
	// One replacement, one index rebuild - readers see either the whole old
	// set or the whole new one, never a table mid-refresh.
	if err := env.translationTable.ReplaceJobEntries(jobname, entryList); err != nil {
		logger.ErrorLogger().Println(err)
	}
}

func (env *Environment) RemoveServiceEntries(jobname string) {
	err := env.translationTable.RemoveByJobName(jobname)
	if err != nil {
		logger.ErrorLogger().Printf("CRITICAL-ERROR: %v", err)
	}
}

func (env *Environment) RemoveNsIPEntries(nsip string) {
	_ = env.translationTable.RemoveByNsip(net.IP(nsip))
}

func (env *Environment) generateAddress() (net.IP, error) {
	var result net.IP
	if len(env.addrCache) > 0 {
		result, env.addrCache = env.addrCache[0], env.addrCache[1:]
	} else {
		result = env.nextContainerIP
		if env.totNextAddr < 62 {
			env.totNextAddr++
		} else {
			logger.ErrorLogger().Printf("exhausted IPv4 address space")
			return result, errors.New("IPv4 address space exhausted")
		}
		env.nextContainerIP = network.NextIPv4(env.nextContainerIP, 1)
	}
	return result, nil
}

func (env *Environment) generateIPv6Address() (net.IP, error) {
	var result net.IP
	if len(env.addrCachev6) > 0 {
		result, env.addrCachev6 = env.addrCachev6[0], env.addrCachev6[1:]
	} else {
		result = env.nextContainerIPv6
		if env.totNextAddrv6 < 255 {
			env.totNextAddrv6++
		} else {
			logger.ErrorLogger().Printf("exhausted IPv6 address space")
			return result, errors.New("IPv6 address space exhausted")
		}
		env.nextContainerIPv6 = network.NextIPv6(env.nextContainerIPv6, 1)
	}
	return result, nil
}

func (env *Environment) freeContainerAddress(ip net.IP) {
	// if ip is an IPv4 addr
	if err := ip.To4(); err != nil {
		env.addrCache = append(env.addrCache, ip)
	} else
	// else check whether it is a correct IPv6 address
	// this cannot be an IPv4-to-IPv6 mapped IPv6 addr, as we handle IPv4 beforehand
	if err = ip.To16(); err != nil {
		env.addrCachev6 = append(env.addrCachev6, ip)
	}
}
