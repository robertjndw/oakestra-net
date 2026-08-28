package TableEntryCache

import (
	"NetManager/events"
	"NetManager/logger"
	"errors"
	"log"
	"net"
	"net/netip"
	"regexp"
	"sync"
)

// nameRegexp validates Appname/Appns/Servicename/Servicenamespace. Compiled
// once at package init instead of on every call to isValid - isValid runs
// once per table mutation, not per packet, but there is no reason to pay for
// a regexp compile on every insert either.
var nameRegexp = regexp.MustCompile("^[a-zA-Z0-9]{1,30}$")

type TableEntry struct {
	JobName          string      `json:"job_name"`
	Appname          string      `json:"appname"`
	Appns            string      `json:"appns"`
	Servicename      string      `json:"servicename"`
	Servicenamespace string      `json:"servicenamespace"`
	Instancenumber   int         `json:"instancenumber"`
	Cluster          int         `json:"cluster"`
	Nodeip           net.IP      `json:"nodeip"`
	Nodeport         int         `json:"nodeport"`
	Nsip             net.IP      `json:"nsip"`
	Nsipv6           net.IP      `json:"nsipv6"`
	ServiceIP        []ServiceIP `json:"serviceIP"`
	// activity tracks when this job was last used by the packet path, so the
	// MQTT interest timer knows when to let the subscription expire. It's a
	// pointer shared by every TableEntry copy for the same JobName (assigned
	// once in Add), so Touch is a single atomic store - no lock, no map
	// lookup, safe to call per packet.
	activity *events.Activity `json:"-"`
}

// Touch marks this entry's job as just used. Safe to call on every packet.
func (e *TableEntry) Touch() {
	if e.activity != nil {
		e.activity.Touch()
	}
}

type ServiceIpType int

const (
	InstanceNumber ServiceIpType = iota
	Closest        ServiceIpType = iota
	RoundRobin     ServiceIpType = iota
)

type ServiceIP struct {
	IpType     ServiceIpType `json:"ip_type"`
	Address    net.IP        `json:"address"`
	Address_v6 net.IP        `json:"address_v6"`
}

type TableManager struct {
	translationTable []TableEntry
	// byServiceIP and byNsIP index translationTable by address so the packet
	// path (SearchByServiceIP/SearchByNsIP) doesn't have to scan the whole
	// table. They hold copies of TableEntry, never pointers into
	// translationTable: removeByIndex swap-removes and Add can reallocate the
	// backing array, either of which would leave a pointer into the old array
	// dangling/stale. Rebuilt wholesale on every mutation - mutations happen
	// on deployment/MQTT events, not per packet, so an O(n) rebuild here is
	// the cheap side of the trade.
	byServiceIP map[netip.Addr][]TableEntry
	byNsIP      map[netip.Addr]TableEntry
	rwlock      sync.RWMutex
}

func NewTableManager() TableManager {
	return TableManager{
		translationTable: make([]TableEntry, 0),
		byServiceIP:      make(map[netip.Addr][]TableEntry),
		byNsIP:           make(map[netip.Addr]TableEntry),
		rwlock:           sync.RWMutex{},
	}
	// TODO cleanup of old entry every X seconds
}

// AddrFromIP converts a net.IP into a netip.Addr suitable for use as a map
// key. Unmap is mandatory: net.ParseIP("10.0.0.1") stores a 16-byte
// IPv4-in-IPv6 form, and netip.AddrFromSlice on 16 bytes returns an
// Is4In6 address - which compares unequal (different internal
// representation) to the plain Is4 address that iputils builds directly
// from the wire bytes of a real IPv4 packet, even though both print the
// same. Unmap normalizes 4-in-6 down to Is4 and is a no-op for a genuine
// IPv6 address, so it is safe to call unconditionally.
func AddrFromIP(ip net.IP) (netip.Addr, bool) {
	if ip == nil {
		return netip.Addr{}, false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// rebuildIndexesLocked recomputes byServiceIP/byNsIP from translationTable.
// Caller must hold rwlock for writing.
func (t *TableManager) rebuildIndexesLocked() {
	byServiceIP := make(map[netip.Addr][]TableEntry, len(t.byServiceIP))
	byNsIP := make(map[netip.Addr]TableEntry, len(t.translationTable))
	for _, entry := range t.translationTable {
		if addr, ok := AddrFromIP(entry.Nsip); ok {
			byNsIP[addr] = entry
		}
		if addr, ok := AddrFromIP(entry.Nsipv6); ok {
			byNsIP[addr] = entry
		}
		for _, sip := range entry.ServiceIP {
			if addr, ok := AddrFromIP(sip.Address); ok {
				byServiceIP[addr] = append(byServiceIP[addr], entry)
			}
			if addr, ok := AddrFromIP(sip.Address_v6); ok {
				byServiceIP[addr] = append(byServiceIP[addr], entry)
			}
		}
	}
	t.byServiceIP = byServiceIP
	t.byNsIP = byNsIP
}

func (t *TableManager) Add(entry TableEntry) error {
	if t.isValid(entry) {
		entry.activity = events.GetOrCreate(entry.JobName)
		t.rwlock.Lock()
		defer t.rwlock.Unlock()
		t.translationTable = append(t.translationTable, entry)
		t.rebuildIndexesLocked()
		return nil
	}
	return errors.New("InvalidEntry")
}

// remove by Namespace IP, which can be either in IPv4 or IPv6 format
func (t *TableManager) RemoveByNsip(nsip net.IP) error {
	logger.DebugLogger().Printf("Remove by Nsip tableManager: %v", t)

	t.rwlock.Lock()
	defer t.rwlock.Unlock()

	found := -1
	// this will need to be optimised for IPv6, since that will be hell performance wise
	for i, tableElement := range t.translationTable {
		if tableElement.Nsip.Equal(nsip) || tableElement.Nsipv6.Equal(nsip) {
			found = i
			break
		}
	}

	return t.removeByIndex(found)
}

func (t *TableManager) RemoveByJobName(jobname string) error {
	t.rwlock.Lock()
	defer t.rwlock.Unlock()

	elems := len(t.translationTable)
	for i := 0; i < elems; i++ {
		if t.translationTable[i].JobName == jobname {
			err := t.removeByIndex(i)
			if err != nil {
				return err
			}
			elems = elems - 1
			i = i - 1
		}
	}
	return nil
}

func (t *TableManager) removeByIndex(index int) error {
	if index > -1 {
		logger.DebugLogger().Printf("Removing from TableManager: %v", t.translationTable[index])
		t.translationTable[index] = t.translationTable[len(t.translationTable)-1]
		t.translationTable = t.translationTable[:len(t.translationTable)-1]
		t.rebuildIndexesLocked()
		return nil
	}
	return errors.New("entry not found")
}

// SearchByServiceIP looks up entries by ServiceIP. O(1) index lookup - the
// previous implementation scanned every entry's ServiceIP list on every
// call, on the packet path, per packet. The returned slice is the index's
// own bucket, not a copy: rebuildIndexesLocked always replaces byServiceIP
// wholesale rather than mutating a published bucket in place, so it's safe
// to hand out directly. It's capped at its current length so an append by
// the caller can't spill into (and silently reuse) the map's own capacity.
func (t *TableManager) SearchByServiceIP(ip net.IP) []TableEntry {
	addr, ok := AddrFromIP(ip)
	if !ok {
		return nil
	}
	t.rwlock.RLock()
	defer t.rwlock.RUnlock()
	matches := t.byServiceIP[addr]
	return matches[:len(matches):len(matches)]
}

// SearchByNsIP looks up a single entry by namespace IP. O(1) index lookup -
// see SearchByServiceIP.
func (t *TableManager) SearchByNsIP(ip net.IP) (TableEntry, bool) {
	addr, ok := AddrFromIP(ip)
	if !ok {
		return TableEntry{}, false
	}
	t.rwlock.RLock()
	defer t.rwlock.RUnlock()
	entry, found := t.byNsIP[addr]
	return entry, found
}

func (t *TableManager) SearchByNodeIp(ip net.IP) []TableEntry {
	result := make([]TableEntry, 0)
	t.rwlock.RLock()
	defer t.rwlock.RUnlock()
	for _, tableElement := range t.translationTable {
		if tableElement.Nodeip.Equal(ip) {
			result = append(result, tableElement)
		}
	}
	return result
}

func (t *TableManager) SearchByJobName(jobname string) []TableEntry {
	t.rwlock.RLock()
	defer t.rwlock.RUnlock()
	results := make([]TableEntry, 0)
	for _, tableElement := range t.translationTable {
		if tableElement.JobName == jobname {
			results = append(results, tableElement)
		}
	}
	return results
}

// Sanity check for Appname and namespace
// 0<len(Appname)<11
// 0<len(Appns)<11
// 0<len(Servicename)<11
// 0<len(Servicenamespace)<11
// Instancenumber>0
// Cluster>0
// Nodeip != nil
// Nsip != nil
// Nsipv6 != nil
// len(entry.ServiceIP)>0
func (t *TableManager) isValid(entry TableEntry) bool {
	if !nameRegexp.MatchString(entry.Appname) {
		log.Println("TranslationTable: Invalid Entry, wrong appname:", entry.Appname)
		return false
	}
	if !nameRegexp.MatchString(entry.Appns) {
		log.Println("TranslationTable: Invalid Entry, wrong appns:", entry.Appns)
		return false
	}
	if !nameRegexp.MatchString(entry.Servicename) {
		log.Println("TranslationTable: Invalid Entry, wrong servicename:", entry.Servicename)
		return false
	}
	if !nameRegexp.MatchString(entry.Servicenamespace) {
		log.Println("TranslationTable: Invalid Entry, wrong servicens:", entry.Servicenamespace)
		return false
	}
	if entry.Instancenumber < 0 {
		log.Println("TranslationTable: Invalid Entry, wrong instancenumber")
		return false
	}
	if entry.Cluster < 0 {
		log.Println("TranslationTable: Invalid Entry, wrong cluster")
		return false
	}
	if entry.Nodeip == nil {
		log.Println("TranslationTable: Invalid Entry, wrong nodeip")
		return false
	}
	if entry.Nsip == nil {
		log.Println("TranslationTable: Invalid Entry, wrong nsip")
		return false
	}
	if entry.Nsipv6 == nil {
		log.Println("TranslationTable: Invalid Entry, wrong nsipv6")
		return false
	}
	if len(entry.ServiceIP) < 1 {
		log.Println("TranslationTable: Invalid Entry, wrong serviceip")
		return false
	}
	return true
}

// IsRouteStillValid checks whether the full cached route (namespace IP, node
// IP and node port) still matches an entry in table. Checking nsip alone is
// not enough: a route refresh can reassign an instance to a different node
// while its Nsip/Nsipv6 stays the same, and a cache hit that only compares
// nsip would then keep tunnelling to the stale node forever (cache hits
// refresh lastUsed, so a stale-but-active flow never ages out on its own).
func IsRouteStillValid(nsip netip.Addr, nodeip netip.Addr, nodeport int, table []TableEntry) bool {
	for i := range table {
		entry := &table[i]
		if entry.Nodeport != nodeport {
			continue
		}
		entryNodeip, ok := AddrFromIP(entry.Nodeip)
		if !ok || entryNodeip != nodeip {
			continue
		}
		if entryNsip, ok := AddrFromIP(entry.Nsip); ok && entryNsip == nsip {
			return true
		}
		if entryNsipv6, ok := AddrFromIP(entry.Nsipv6); ok && entryNsipv6 == nsip {
			return true
		}
	}
	return false
}
