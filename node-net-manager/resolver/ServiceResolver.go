package resolver

import (
	"NetManager/TableEntryCache"
	"NetManager/logger"
	"NetManager/model"
	"NetManager/mqtt"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

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
type Resolver interface {
	// GetTableEntryByServiceIP returns the entries for addr, starting
	// background resolution on a miss. Resolution needs a blocking MQTT round
	// trip and must never happen on the packet path - see resolveServiceIPOnce.
	GetTableEntryByServiceIP(addr netip.Addr) ServiceLookup
	GetTableEntryByNsIP(addr netip.Addr) (TableEntryCache.TableEntry, bool)
}

// LocalDeployments answers whether a job is deployed on this node. It decouples
// ServiceResolver's MQTT interest bookkeeping (which needs to know when a job
// is no longer needed locally) from the host/namespace management that
// actually tracks deployments.
type LocalDeployments interface {
	IsServiceDeployed(job string) bool
}

// ServiceResolver resolves Service IPs, Namespace IPs and Instance IPs on the
// packet path against the local translation table, kicking off background MQTT
// table queries on a miss.
type ServiceResolver struct {
	translationTable TableEntryCache.TableManager
	deployments      LocalDeployments
	// resolveLock guards pendingResolves and failedServiceIPs. Both maps are
	// created lazily so the zero ServiceResolver stays usable.
	resolveLock      sync.Mutex
	pendingResolves  map[netip.Addr]chan struct{} // ServiceIP -> closed when its in-flight resolution finishes
	failedServiceIPs map[netip.Addr]time.Time     // ServiceIP -> when resolution last failed
	// tableQuery performs the blocking table query. Nil selects the real MQTT
	// round trip; tests substitute a stub for it.
	tableQuery func(netip.Addr) ([]TableEntryCache.TableEntry, error)
}

// New builds a ServiceResolver backed by a fresh translation table. deployments
// is consulted to decide when a job's MQTT interest can be dropped; a nil
// deployments is fine for tests that never exercise that path.
func New(deployments LocalDeployments) *ServiceResolver {
	return &ServiceResolver{
		translationTable: TableEntryCache.NewTableManager(),
		deployments:      deployments,
	}
}

// IsServiceDeployed forwards to the injected LocalDeployments, which is what
// lets ServiceResolver satisfy the mqtt package's interest-registration
// interface directly. A nil LocalDeployments (e.g. a resolver built without
// one for tests) reports false rather than panicking.
func (r *ServiceResolver) IsServiceDeployed(job string) bool {
	if r.deployments == nil {
		return false
	}
	return r.deployments.IsServiceDeployed(job)
}

// GetTableEntriesOnNode performs a search in the local ServiceCache for entries with the NodeIp of this node
func (r *ServiceResolver) GetTableEntriesOnNode() []TableEntryCache.TableEntry {
	ip := net.ParseIP(model.NetConfig.NodePublicAddress)
	return r.translationTable.SearchByNodeIp(ip)
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
func (r *ServiceResolver) GetTableEntryByServiceIP(addr netip.Addr) ServiceLookup {
	// If entry already available
	table, generation := r.translationTable.SearchByServiceIP(addr)
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
	return ServiceLookup{Resolving: r.resolveServiceIPOnce(addr)}
}

// resolveServiceIPOnce starts background resolution for ip and returns a
// channel that is closed once the attempt finishes, so a caller can hold onto
// the packet that triggered it. Returns nil when no attempt is running: a
// recent one already failed (see negativeResolveCacheTTL) or too many are
// already in flight, in which case the caller should drop the packet.
func (r *ServiceResolver) resolveServiceIPOnce(key netip.Addr) <-chan struct{} {
	r.resolveLock.Lock()

	if done, ok := r.pendingResolves[key]; ok {
		r.resolveLock.Unlock()
		return done
	}

	if failedAt, ok := r.failedServiceIPs[key]; ok {
		if time.Since(failedAt) < negativeResolveCacheTTL {
			r.resolveLock.Unlock()
			return nil
		}
	}

	if len(r.pendingResolves) >= maxConcurrentResolves {
		r.resolveLock.Unlock()
		return nil
	}

	if r.pendingResolves == nil {
		r.pendingResolves = make(map[netip.Addr]chan struct{})
	}
	done := make(chan struct{})
	r.pendingResolves[key] = done
	r.resolveLock.Unlock()

	go func() {
		err := r.resolveServiceIP(key)

		r.resolveLock.Lock()
		delete(r.pendingResolves, key)
		if err != nil {
			r.rememberFailureLocked(key)
		} else {
			delete(r.failedServiceIPs, key)
		}
		r.resolveLock.Unlock()

		close(done)
	}()

	return done
}

// rememberFailureLocked records a failed resolution, first sweeping expired
// entries and - if every entry is still fresh - dropping the map wholesale
// rather than letting it grow. Worst case that costs a handful of ServiceIPs
// one extra query each.
func (r *ServiceResolver) rememberFailureLocked(key netip.Addr) {
	if r.failedServiceIPs == nil {
		r.failedServiceIPs = make(map[netip.Addr]time.Time)
	}

	if len(r.failedServiceIPs) >= maxFailedServiceIPs {
		now := time.Now()
		for k, failedAt := range r.failedServiceIPs {
			if now.Sub(failedAt) >= negativeResolveCacheTTL {
				delete(r.failedServiceIPs, k)
			}
		}
		if len(r.failedServiceIPs) >= maxFailedServiceIPs {
			r.failedServiceIPs = make(map[netip.Addr]time.Time)
		}
	}

	r.failedServiceIPs[key] = time.Now()
}

// resolveServiceIP performs the actual (blocking) table query and populates
// the translation table. Must only ever run off the packet path.
//
// Every path that leaves addr unresolved has to report an error, not just log
// one: resolveServiceIPOnce reads the return value to decide whether to arm
// the negative cache, so returning nil after a failed install would clear it
// and let the very next packet start another MQTT round trip.
func (r *ServiceResolver) resolveServiceIP(addr netip.Addr) error {
	entryList, err := r.queryTable(addr)
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

	if err := r.translationTable.ReplaceJobEntries(jobName, entryList); err != nil {
		return err
	}

	mqtt.MqttRegisterInterest(jobName, r)
	// register interest for sip as well to avoid querying the address too many times
	mqtt.MqttRegisterInterest(addr.String(), r)
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

func (r *ServiceResolver) queryTable(addr netip.Addr) ([]TableEntryCache.TableEntry, error) {
	if r.tableQuery != nil {
		return r.tableQuery(addr)
	}
	return tableQueryByIP(addr)
}

// GetTableEntryByNsIP Given a NamespaceIP finds the table entry. This search is local because the networking component MUST have all
// the entries for the local deployed services.
func (r *ServiceResolver) GetTableEntryByNsIP(addr netip.Addr) (TableEntryCache.TableEntry, bool) {
	return r.translationTable.SearchByNsIP(addr)
}

// RefreshServiceTable force a table query refresh for a service
func (r *ServiceResolver) RefreshServiceTable(jobname string) {
	logger.DebugLogger().Printf("Requested table query refresh for %s", jobname)
	entryList, err := tableQueryByJobName(jobname, true)
	if err != nil {
		return
	}
	// One replacement, one index rebuild - readers see either the whole old
	// set or the whole new one, never a table mid-refresh.
	if err := r.translationTable.ReplaceJobEntries(jobname, entryList); err != nil {
		logger.ErrorLogger().Println(err)
	}
}

func (r *ServiceResolver) RemoveServiceEntries(jobname string) {
	err := r.translationTable.RemoveByJobName(jobname)
	if err != nil {
		logger.ErrorLogger().Printf("CRITICAL-ERROR: %v", err)
	}
}

// RemoveNsIPEntry removes the translation table entry that owns ip. Used by
// the container/unikernel teardown paths.
func (r *ServiceResolver) RemoveNsIPEntry(ip net.IP) error {
	return r.translationTable.RemoveByNsip(ip)
}
