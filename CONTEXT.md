# Domain glossary

The ubiquitous language for oakestra-net. Use these terms in code, comments, commit messages and reviews. Where a term already has a name in the code, that name is given so the two stay tied together.

## Addressing

**Service IP** (also *Service VIP*) — an address in `10.30.0.0/16` (or the IPv6 proxy prefix) that names a *service*, not a destination. It carries a load-balancing policy rather than a location, which is what makes the overlay semantic. A packet addressed to one must be translated before it can leave the node. In code: `TableEntryCache.ServiceIP`.

**Instance IP** — the stable address identifying one deployed *instance* of a service. It is the address that instance's own proxy sources its replies from, which is why the reverse translation can key on it. In code: the `ServiceIP` entry whose `IpType` is `InstanceNumber`.

**Namespace IP** — the address a container actually holds inside its network namespace, allocated from the node's bridge subnetwork. In code: `TableEntry.Nsip` / `Nsipv6`.

**Proxy subnetwork** — the prefix the datapath tests destination addresses against to decide whether a packet needs translation at all. In code: `GoProxyTunnel.ProxyIPv4Prefix` / `ProxyIPv6Prefix`.

## Resolution

**Job** — one deployed service, named `app.appns.service.servicens`. The unit a table query answers for, and the unit an interest is registered against.

**Table entry** — one instance of one job: its namespace IPs, the node hosting it, that node's tunnel port, and the Service IPs it answers to. In code: `TableEntryCache.TableEntry`.

**Translation table** — the node's local view of which instances exist where, indexed by Service IP and by namespace IP. In code: `TableEntryCache.TableManager`.

**Generation** — a counter bumped on every rebuild of the translation table's indexes. A route chosen under the current generation is known to still be current, which lets the datapath skip revalidating it against every replica.

**Table query** — the blocking MQTT round trip that asks the cluster where a job's instances are. Costs up to 5 s and must never run on the packet path.

**Interest** — a subscription telling the cluster this node still cares about a job's updates. Self-destructs once the job goes unused locally.

**ServiceResolver** — the module that owns everything above: the translation table, background resolution of a Service IP, the negative cache for addresses that failed to resolve, the generation counter, and the MQTT interest lifetime. It is what the datapath depends on, and it is deliberately free of any host-networking dependency. In code: package `resolver`, type `ServiceResolver`, behind the `Resolver` interface.

## Datapath

**Datapath** — the per-packet path: read, parse, translate, forward. Everything on it is measured in nanoseconds and must not allocate, block, or take a process-global lock.

**Flow** — one translated conversation, identified by the full 5-tuple in both directions. In code: `proxy.ConversionEntry`.

**Route** — the choice of *which* instance a flow was pinned to, plus the node and port to tunnel it through. Cached on the flow and revalidated only when the generation moves.

**Tunnel** — the UDP transport between two nodes, one socket per peer, on the reserved port `50103`.

**Replay** — packets held while their Service IP is still resolving, re-run in arrival order once resolution finishes, so a cold flow's first datagram is not silently lost.

## Control plane

**Root service manager** — allocates Service IPs globally and propagates routes between clusters.

**Cluster service manager** — receives routes from root and distributes them to nodes over MQTT.

**Node net manager** — the per-node daemon that owns namespaces, the translation table and the datapath.
