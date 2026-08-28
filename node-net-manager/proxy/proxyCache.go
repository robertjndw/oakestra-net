package proxy

import (
	"NetManager/logger"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// ConversionEntry is one translated flow. A flow is identified by the full
// 5-tuple in both directions: identifying it by destination port alone (which
// this cache used to do) collides as soon as one local socket talks to two
// different Service VIPs on the same port - the common UDP shape - and lets a
// reply for one VIP be reverse-translated as though it belonged to the other.
type ConversionEntry struct {
	srcip         netip.Addr
	dstip         netip.Addr
	dstServiceIp  netip.Addr
	srcInstanceIp netip.Addr
	// dstInstanceIp is the address the far end's replies will arrive from. It
	// is not dstip: the remote node's own outgoingProxy translates the reply,
	// because our srcInstanceIp is inside its proxy subnetwork too, so the
	// reply is sourced from the target's instance IP. Without it the reverse
	// lookup cannot tell two flows apart that share a local port and a remote
	// port. Zero when the table entry has no InstanceNumber ServiceIP, which
	// the reverse lookup treats as "matches any remote".
	dstInstanceIp netip.Addr
	srcport       int
	dstport       int
	protocol      uint8
	// dstNode/dstNodePort cache which node dstip actually lives on, so the
	// packet path doesn't need a second table lookup by namespace IP.
	dstNode     netip.Addr
	dstNodePort int
	// routeGen is the translation table generation this route was chosen
	// from. While it still matches, the route is known to be current and the
	// per-replica revalidation scan can be skipped entirely.
	routeGen uint64
	lastUsed int64
}

// conversionBucket holds every flow whose *local* port is this bucket's index.
// Both directions key on the local port - outgoing on its source port, ingoing
// on the reply's destination port - so one direct index serves both without
// hashing anything on the packet path.
type conversionBucket struct {
	entries []ConversionEntry
}

const (
	// maxFlowsPerPort bounds one local port's flow list. A single socket
	// talking to more distinct endpoints than this is possible but unusual;
	// past the cap the least recently used flow is recycled.
	maxFlowsPerPort = 64
	// cacheShards is the number of striped locks over the bucket array.
	// Sharding keeps eviction from taking a lock that covers every flow on
	// the node while the datapath is trying to translate.
	cacheShards = 256
)

type ProxyCache struct {
	// One bucket per local port number. Higher mem usage but lower cpu usage.
	cache []conversionBucket
	locks [cacheShards]sync.Mutex
	frags *fragmentCache
}

// coarseClock is a 1Hz-updated Unix-seconds clock shared by every
// ProxyCache entry. Recording "last used" on every cache hit doesn't need
// second-level precision, so entries read this instead of each calling
// time.Now() (a vDSO call) on every packet.
var coarseClock atomic.Int64

func init() {
	coarseClock.Store(time.Now().Unix())
	go func() {
		ticker := time.NewTicker(time.Second)
		for range ticker.C {
			coarseClock.Store(time.Now().Unix())
		}
	}()
}

func NewProxyCache() *ProxyCache {
	cache := &ProxyCache{
		cache: make([]conversionBucket, 65536),
		frags: newFragmentCache(),
	}
	cache.runEvictionJob(30*time.Second, 1*time.Minute)
	return cache
}

func shardOf(localPort int) int { return localPort & (cacheShards - 1) }

// runEvictionJob starts a goroutine that periodically evicts old cache entries.
func (cache *ProxyCache) runEvictionJob(interval time.Duration, timeout time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			cache.evictOldEntries(timeout)
			cache.frags.evictExpired()
		}
	}()
}

// evictOldEntries removes flows that have not been used for the duration of
// the timeout. It walks one shard at a time so it never holds a lock covering
// the whole table.
func (cache *ProxyCache) evictOldEntries(timeout time.Duration) {
	now := coarseClock.Load()
	timeoutSeconds := int64(timeout.Seconds())
	evictedCount := 0

	for shard := range cache.locks {
		cache.locks[shard].Lock()
		for port := shard; port < len(cache.cache); port += cacheShards {
			bucket := &cache.cache[port]
			kept := bucket.entries[:0]
			for _, entry := range bucket.entries {
				if now-entry.lastUsed > timeoutSeconds {
					evictedCount++
					continue
				}
				kept = append(kept, entry)
			}
			if len(kept) == 0 {
				bucket.entries = nil
			} else {
				bucket.entries = kept
			}
		}
		cache.locks[shard].Unlock()
	}

	if evictedCount > 0 {
		logger.InfoLogger().Printf("Evicted %d entries from cache", evictedCount)
	}
}

// RetrieveByServiceIP looks up the outgoing flow for a packet leaving the
// local namespace. tableGen is the current translation table generation; if it
// still matches the one the route was chosen under, the caller can skip
// revalidating the route against every replica.
func (cache *ProxyCache) RetrieveByServiceIP(
	protocol uint8, srcip netip.Addr, instanceIP netip.Addr, srcport int,
	dstServiceIp netip.Addr, dstport int,
) (ConversionEntry, bool) {
	shard := shardOf(srcport)
	cache.locks[shard].Lock()
	defer cache.locks[shard].Unlock()

	bucket := &cache.cache[srcport]
	for i := range bucket.entries {
		entry := &bucket.entries[i]
		if entry.protocol == protocol &&
			entry.dstport == dstport &&
			entry.dstServiceIp == dstServiceIp &&
			entry.srcip == srcip &&
			entry.srcInstanceIp == instanceIP {
			entry.lastUsed = coarseClock.Load()
			return *entry, true
		}
	}
	return ConversionEntry{}, false
}

// MarkRouteCurrent records that a cached flow was revalidated against
// translation table generation gen, so later packets on the same flow can skip
// the scan while the table stays unchanged.
func (cache *ProxyCache) MarkRouteCurrent(entry ConversionEntry, gen uint64) {
	shard := shardOf(entry.srcport)
	cache.locks[shard].Lock()
	defer cache.locks[shard].Unlock()

	bucket := &cache.cache[entry.srcport]
	for i := range bucket.entries {
		if bucket.entries[i].sameFlowAs(&entry) {
			bucket.entries[i].routeGen = gen
			return
		}
	}
}

// RetrieveByInstanceIp looks up the flow a reply belongs to, so it can be
// reverse-translated. The arguments are read off the reply packet: it is
// addressed to the local namespace IP and local port the flow originated from,
// and sourced from the remote instance IP and port it was sent to.
func (cache *ProxyCache) RetrieveByInstanceIp(
	protocol uint8, localNsIP netip.Addr, localPort int,
	remoteIP netip.Addr, remotePort int,
) (ConversionEntry, bool) {
	shard := shardOf(localPort)
	cache.locks[shard].Lock()
	defer cache.locks[shard].Unlock()

	bucket := &cache.cache[localPort]
	for i := range bucket.entries {
		entry := &bucket.entries[i]
		if entry.protocol != protocol || entry.dstport != remotePort || entry.srcip != localNsIP {
			continue
		}
		// A zero dstInstanceIp means the route had no InstanceNumber
		// ServiceIP to predict the reply source from; fall back to the
		// looser match rather than dropping the flow's replies entirely.
		if entry.dstInstanceIp.IsValid() && entry.dstInstanceIp != remoteIP {
			continue
		}
		entry.lastUsed = coarseClock.Load()
		return *entry, true
	}
	return ConversionEntry{}, false
}

// sameFlowAs compares the full forward identity of two entries. Anything less
// - notably comparing destination port alone - conflates distinct flows.
func (e *ConversionEntry) sameFlowAs(other *ConversionEntry) bool {
	return e.protocol == other.protocol &&
		e.srcport == other.srcport &&
		e.dstport == other.dstport &&
		e.srcip == other.srcip &&
		e.srcInstanceIp == other.srcInstanceIp &&
		e.dstServiceIp == other.dstServiceIp
}

// Add inserts a flow, replacing the entry for the same flow if there is one.
func (cache *ProxyCache) Add(entry ConversionEntry) {
	entry.lastUsed = coarseClock.Load()

	shard := shardOf(entry.srcport)
	cache.locks[shard].Lock()
	defer cache.locks[shard].Unlock()

	bucket := &cache.cache[entry.srcport]
	for i := range bucket.entries {
		if bucket.entries[i].sameFlowAs(&entry) {
			bucket.entries[i] = entry
			return
		}
	}

	if len(bucket.entries) < maxFlowsPerPort {
		bucket.entries = append(bucket.entries, entry)
		return
	}

	// Bucket full: recycle the least recently used flow.
	oldest := 0
	for i := range bucket.entries {
		if bucket.entries[i].lastUsed < bucket.entries[oldest].lastUsed {
			oldest = i
		}
	}
	bucket.entries[oldest] = entry
}
