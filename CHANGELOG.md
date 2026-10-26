# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). See
[VERSIONING.md](VERSIONING.md) for the policy.

## [Unreleased]

## [5.1.1] — 2026-10-26

### Changed

- tokio 1.53.3 -> 1.54.1 (lock only).

## [5.1.0] — 2026-10-25

### Added

- `DialogueEngine::claim_expired`, `DialogueEngine::expire` and
  `DialogueEngine::release_claim`: the two halves of `sweep`, for a caller
  that runs the timers of each dialogue somewhere else than the task that
  finds them due. `dialogue::tid_lane` gives the lane of a dialogue by its
  transaction id, the same one `dialogue_lane` gives its messages.

### Fixed

- **A slow timeout handler no longer holds up the node.** The dialogue timers
  ran on the task that hands inbound messages to the dialogue lanes, so while
  an invocation-timeout or idle-timeout handler (a script among them) ran,
  no inbound dialogue was dispatched. The timers of a dialogue now run on its
  own lane, on a blocking thread like every other handler turn, and the Abort
  a timer produces is still sent. A handler turn that runs for more than 10 s
  is logged as an error every 10 s, naming its lane.
- **The loopback `Node` (`siphon.configure(...)`) no longer holds its engine
  lock while a handler runs.** A handler that called back into the node, or
  another thread that did while one ran, could deadlock. Registering a
  handler while one is running is refused with `SigtranError`. A node or
  handler that `configure` or a re-registration replaces is released after the
  lock, not under it.
- **Script handlers on the live node run on siphon's script executor, never
  on a tokio thread.** A dialogue turn used to call its handler attached on
  the lane's blocking thread, and an `async def` handler ran there on an
  event loop of its own. A thread of tokio that waits attached holds every
  garbage collection's stop-the-world open. Now the handler is called in a
  siphon executor job; an `async def` handler finishes on siphon's
  asyncio pool (bounded by its coroutine timeout, then cancelled)
  and what it staged is read in a second job, while the lane waits released.
  The loopback `Node` still runs handlers on the calling thread; its own
  event loop is used only when siphon is not running. The `begin(...)`
  helpers use siphon's awaitable bridge, and an originated `Begin` is built
  on a blocking thread too.

### Changed

- Requires siphon-sip 1.15.4 or later, for its executor dispatch helpers.
  `pyo3-async-runtimes` is no longer a direct dependency. A `clippy.toml` disallows the waits that park a thread
  (`block_on`, `block_in_place`, `thread::sleep`, blocking receives and
  connects) outside tests, benches and examples.

## [5.0.0] — 2026-10-22

### Added

- **Level 2 of an M2PA link** as RFC 4165 and ITU-T Q.703 have it. The Link
  Status exchange runs on timers: Out of Service when the association comes up,
  Alignment, Proving Normal or Emergency repeated for the proving period, Ready;
  T1, T2, T3, T4 (normal and emergency), T6 and T7 are per-link keys in a new
  `m2pa:` block of an association, in milliseconds, with the Q.703 12.3 values
  as defaults. A link that fails or cannot be aligned starts alignment again
  after `restart_ms` (Q.704 12.2.2, T17). Processor Outage / Recovered and Busy
  / Busy Ended from the peer are acted on (traffic is held, T6 and T7 are
  handled as 4.1.4 and 4.1.5 say); this node never originates them.
- **The signalling link test** (ITU-T Q.707 2.2). A test message from the peer
  is answered with its pattern. The node tests each link after alignment and
  every T2 after that; a link is an egress for routing only once its test has
  passed, and two failures in a row take it out of service. `link_test:` on a
  linkset (`enabled`, `t1_ms`, `t2_ms`, `pattern`) and `slc:` on a link are new
  keys, all with defaults.
- **The buffers a failed link holds can be retrieved** (`transport::M2paLink`:
  `bsnt`, `retrieve`), as RFC 4165 4.2.3 needs for changeover, which uses
  them (see below).
- `sigtran_m2pa_discarded_total{reason}`, `sigtran_m2pa_link_failures_total{reason}`,
  `sigtran_link_tests_total{result}`, and `link-test` as a `reason` of
  `sigtran_rx_discarded_total`. Every message a link receives or is handed and
  does not carry is in one of them, with a line on stderr.
- **Signalling network management of a transfer point** (ITU-T Q.704), one
  task per routing domain, for linksets:
  - *Changeover and changeback* (clauses 5 and 6). When a link fails, its
    traffic is buffered, an extended changeover order (XCO / XCA of Q.2210
    9.8.1, as RFC 4165 4.2.3 has M2PA links use) carries the last sequence
    number accepted, and on the acknowledgement the messages the far end does
    not have go out again on the alternative links ahead of the buffer: none
    lost, none twice. T1 (time-controlled) and T2 cover a far end that cannot
    be asked or does not answer; an order from the far end is obeyed and
    acknowledged; ECO, ECA, COO and COA are answered as 5.6 and 5.7 say. When
    the link returns, a changeback declaration goes out on each link that
    carried its traffic and the buffer follows the acknowledgements (T4, T5);
    a linkset that returns takes its traffic back after T3.
  - *Route management* (clause 13). Transfer-prohibited and transfer-allowed
    are sent to the adjacent points when a destination becomes inaccessible or
    accessible through this node (broadcast method), when this node starts or
    stops routing a destination through a point (13.2.2 i, 13.3.2 i), and in
    answer to a message that cannot be transferred (response method, T8).
    Received ones mark that one route: traffic moves at once on a
    transfer-prohibited (forced rerouting, clause 7) and after T6 on a
    transfer-allowed or -restricted (controlled rerouting, clause 8). A
    prohibited or restricted route is tested every T10, and a route set test
    from a neighbour is answered.
  - *MTP restart* (clause 9): this node's own (T18, T20, traffic from the
    linksets discarded until it ends), that of an adjacent point (T21: no
    traffic to it before its traffic restart allowed), and T19.
  - *Management inhibiting* (clause 10) at the far end's request: granted or
    denied, the link taken out of traffic and put back, the inhibit tests run
    and answered. This node never asks to inhibit a link itself.
  - Transfer-controlled is counted and published; none is sent.
- **Routes of equal priority share the load** by signalling link selection
  (Q.704 2.3.2 b): `Router::route_for` and `RouteResolver::resolve_for` take
  the selection code, `route_in` and `resolve` are the same with code 0. Each
  code has a normal route and a normal link; when one fails only its codes
  move. A linkset in a combined linkset picks its links by the bits the choice
  of the linkset left over.
- An `mtp3:` block per routing domain: every Q.704 timer the above runs
  (`t1_ms` to `t6_ms`, `t8_ms`, `t10_ms`, `t12_ms`, `t13_ms`, `t18_ms` to
  `t21_ms`, `t23_ms`), `tfp_for_unknown_destination` and `rerouting_buffer`,
  all with the Q.704 16.8 values as defaults.
- `Registry::destination_changes`: every destination that becomes accessible,
  inaccessible, or reached by a restricted route only through this node, and
  every transfer-controlled, is published there once
  (`transport::DestinationChange`).
- `mtp3::management`, the state machine behind all of it, without I/O:
  `Management`, its `Input` and `Action`, `Topology`, `Timers`.
- **M3UA management of a signalling gateway** (RFC 4666), one task per routing
  domain, for the ASPs of its application servers:
  - *ASP and AS state* (4.3). The state of every ASP in every server it is
    configured in, and of every server: inactive, active, pending for T(r)
    (`recovery_ms`, default 2000) with its traffic queued (`pending_queue`),
    and "n" ASPs before a server is active (`required_asps`). All three are
    new keys of an application server.
  - *Notify* (4.3.4.5): AS-INACTIVE, AS-ACTIVE and AS-PENDING to every ASP of
    the server that is not down, after the acknowledgement they follow from;
    the state of the server to an ASP that comes up; Alternate ASP Active,
    ASP Failure and Insufficient ASP Resources Active in AS.
  - *Routing contexts and traffic modes are checked.* An ASP Active or ASP
    Inactive for a routing context the association is not configured in is
    answered with Error, "Invalid Routing Context"; a Traffic Mode Type that is
    not the server's with "Unsupported Traffic Mode Type". In an override
    server the ASP that asks last takes the traffic.
  - *Destinations* (4.5, 4.6). DUNA, DAVA, DRST and SCON are sent to every
    active ASP when level 3 finds a destination inaccessible, accessible,
    restricted or congested, and to an ASP that becomes active for what is
    unavailable then; a DAUD is answered per destination, ranges included;
    while this node's MTP restart runs the destinations behind linksets are
    unavailable to the ASPs.
  - *Between an ASP and a linkset* (1.4.3.2). A transfer-controlled or user
    part unavailable message for the point code of a server becomes a SCON or
    a DUPU; a SCON from an ASP with a Concerned Destination becomes a
    transfer-controlled; DUNA and DAVA from an ASP reach the adjacent points
    as transfer-prohibited and transfer-allowed, as before.
  - *Error* (3.8.1) for what cannot be read or acted on: invalid version,
    unsupported message class or type, unsupported traffic mode type,
    unexpected message, protocol error, invalid parameter value, parameter
    field error, missing parameter, invalid routing context, no configured AS
    for ASP.
  - *Heartbeat* (4.3.4.6): the Heartbeat Data is returned in the
    acknowledgement, and with `m3ua.beat_ms` set this node sends Heartbeat and
    aborts the association of a peer that says nothing for twice that long.
  - *As an ASP* (a `client` association): ASP Up and ASP Active are sent again
    every `m3ua.ack_ms` (T(ack), default 2000) until acknowledged, with
    `m3ua.asp_id` as ASP Identifier; a Notify from the gateway is acted on.
- `transport::Aspm`, the state machine behind ASP and AS state, without I/O,
  with its `AspmInput`, `AspmAction` and `AspmLayout`; `AsState`, `AspState`,
  `NotifyStatus`; `Registry::server_state`; `Router::is_restricted`.
- `sigtran_as_state{as}`, `sigtran_m3ua_management_total{dir,type}`,
  `sigtran_m3ua_error_total{dir,code}`, `sigtran_m3ua_notify_total{dir,status}`,
  `sigtran_m3ua_events_total{event}`, `sigtran_m3ua_discarded_total{reason}`,
  and `routing-context`, `unexpected`, `parameter` and `management` as a
  `reason` of `sigtran_rx_discarded_total`.
- `sigtran_mtp3_management_total{dir,type}`,
  `sigtran_mtp3_procedures_total{procedure}`,
  `sigtran_mtp3_retrieved_total{fate}`, `sigtran_mtp3_discarded_total{reason}`,
  `sigtran_mtp3_link_traffic{link}` and `sigtran_mtp3_restarting`.
  `sigtran_mtp3mg_events_total` now also counts `tfp` and `tfa` received from a
  linkset.

- **A listening association accepts its configured peer** (RFC 4165 4.1.2:
  "it is RECOMMENDED that each endpoint know the IP address (or IP addresses,
  if multi-homing is used) and port number of both endpoints"). `peer_addrs`
  (every address of the peer) and `peer_port` are new keys of a `server`
  association of any adaptation. A peer is the association's when every
  address it presents is listed; anyone else is aborted right after the SCTP
  handshake, which the kernel completes by itself, and nothing they sent is
  read.
- **Associations may share one local address and port.** There is one listener
  per local endpoint, and the associations on it are told apart by the address
  of the peer. A file in which that cannot work (a peer address in two lists
  with no `peer_port` to tell them apart, an association without `peer_addrs`
  next to another, address lists that overlap and differ) does not load, and
  the error names both associations.
- **A `client` association is dialled until it is up, and again after it is
  lost** (RFC 4666 4.3.4.6: "the signalling process SHOULD attempt to
  re-establish communication if it is configured as the client for the
  disconnected M3UA peer"). Each has a task of its own with a back-off that
  doubles from `backoff_initial_ms` to `backoff_max_ms`, less a random part
  (`backoff_jitter_percent`), and a limit per attempt (`connect_timeout_ms`):
  the new `dial:` block of an association, defaults 1 s, 30 s, 20 % and 10 s.
  On the association that was dialled again everything runs as on the first:
  ASP Up and ASP Active, the alignment and the test of a link, and the
  changeback of level 3 to a link that returned.
- `local_addrs` and `local_port` on a `client` association: the addresses and
  the port it is dialled from, for a multihomed local end and for a peer that
  accepts by source address.
- `sigtran_association_dial_attempts_total{assoc}`,
  `sigtran_association_dial_failures_total{assoc,reason}` (`refused`,
  `timeout`, `unreachable`, `local`, `other`) and
  `sigtran_association_dial_backoff_seconds{assoc}`. The log has one line per
  change (first failure of a run, another reason, established, ended) and one
  a minute while nothing changes.
- `sigtran_association_refused_total{reason}` (`unknown-peer`,
  `unlisted-address`, `peer-port`, `duplicate`, `closed`), with a line on
  stderr per refusal, at most one a second per listening endpoint.

### Changed

- **`rasn` 0.29, `tcap` 3, `gsm_map` 4, `gsm_cap` 4 and `inap` 3** (were
  0.28, 2, 3, 3 and 2). Their types are in this crate's API (dialogue and
  component values, the typed MAP and CAP views), so an embedding binary moves
  with this release. rasn 0.29 itself refuses a malformed OPTIONAL member or
  last list element that 0.28 dropped; the strict decoders already refused
  them, and still do.
- **An established association is not displaced by a later one.** A second
  SCTP association for an association that has one waits, unread, for up to
  two seconds for the first to end, and is then aborted and counted. Before,
  the newest took the place of the one before: on an M2PA link the link failed,
  on M3UA the ASP went down. A restart of the same peer from the same addresses
  and port is not affected, SCTP handles it inside the association (RFC 9260
  5.2.4). A peer that lost its association unnoticed and returns from another
  port is refused until the old association has failed (the next packet sent to
  it, or the SCTP heartbeat).
- A `server` association without `peer_addrs` still accepts whoever connects
  first, and now says so at start in a warning. Two of them on the same address
  and port, which failed to bind at start, are now refused when the file is
  loaded.
- **`TransportHandle::start` no longer waits for the `client` associations**
  and no longer fails because one of their peers is absent. It binds every
  listening endpoint, starts the dialling, and returns. Code that sent on a
  `client` association right after the start has to wait for it to carry
  (`Registry::slot(..).is_carrying()`, or the destination being reachable).
- Needs `async-sctp` 1.1: a connect that was refused could wait forever, a
  receive on an association that was aborted while another task was sending
  on it could wait forever, and so could a send that waited for room in the
  send buffer. With an association that is never displaced, a task that never
  ends would have kept its association's place. 1.1 also binds a client
  socket to local addresses before it connects.
- Needs `m2pa` 1.1 (Link Status Out of Service, the acknowledgement-only User
  Data message, the priority in its RFC 4165 bit position), `mtp3` 1.2 (the
  management and link test message codec) and `m3ua` 1.1 (the SCON, DUPU and
  DRST builders, the accessors of the management parameters).
- **An M3UA association carries traffic only as an ASP of an application
  server.** A `server` association that is in no `application_servers` entry
  used to become active on any ASP Active and have its DATA routed; its ASP
  Active is now answered with Error, "No Configured AS for ASP", or "Invalid
  Routing Context" when it names one. Put the association in a server.
- **A peer ASP has to name the routing context and traffic mode the server
  has**, or none. An ASP Active with another routing context or mode used to
  be acknowledged, and DATA with any routing context routed; both are now
  answered with Error and the DATA is not routed.
- DATA from an ASP that is not active is answered with Error, "Unexpected
  Message", where it was only counted.
- A server whose last active ASP leaves stays a route for `recovery_ms` (2 s)
  and queues what arrives, where its route went at once: an alternate route
  takes over that much later. Set `recovery_ms: 0` for the old behaviour.
- Signalling network management (service indicator 0) addressed to the point
  code of an application server is no longer sent to its ASPs in DATA, and
  none is accepted from an ASP in DATA (RFC 4666 1.4.3.2).
- As an ASP the node no longer puts ASP Identifier 1 in every ASP Up: the
  parameter is left out unless `m3ua.asp_id` is set (3.5.1 wants it unique
  among the ASPs of a server). It sends one ASP Active per server.
- The Heartbeat Data of a peer's Heartbeat is returned in the acknowledgement;
  it was dropped.
- A DAUD, DUNA or DAVA entry with a mask is applied to the destinations of
  the routing table in that range; such an entry used to be dropped, the mask
  octet being read as part of the point code.
- SUA associations are unchanged: they keep the plain handshake, without
  Notify, Error or the checks above.
- `sigtran_m2pa_link_state` is `1` only once level 2 is in service; it used to
  be `1` for any link with an association. User data on a link that is not in
  service is counted in `sigtran_m2pa_discarded_total{reason="rx-not-in-service"}`,
  no longer as `out-of-state` in `sigtran_rx_discarded_total`.
- `transport::next_status` is deprecated: alignment is no longer one status
  answered with another.
- **Dialogues are terminated side by side.** `serve_dialogues` handed every
  inbound MSU to one task, which ran each handler to completion before reading
  the next: one slow handler (a script waiting on a store) held up every dialogue
  behind it, and blocked a runtime worker while it ran. Deliveries now go to 32
  lanes keyed on the dialogue's transaction ID, so the messages of one dialogue
  stay in order, and each handler runs on a blocking thread. Four 300 ms
  handlers are answered in under 0.5 s instead of 1.2 s.
- **An `async def` handler reuses an idle event loop.** Each one got a new
  asyncio loop (a selector and a self-pipe socket pair) that was closed again
  after it; a loop the handler leaves with nothing pending is now kept for the
  next one (16 us down to under 5 us per call for a short handler). A loop left
  with a task still pending is closed, as before.
- **A linkset carries traffic later than it did.** A node whose first link
  comes into service runs the MTP restart procedure and discards what arrives
  on its linksets until every adjacent point has sent traffic restart allowed,
  or `mtp3.t18_ms` (20 s) is over; an adjacent point that returns is waited for
  under `mtp3.t21_ms` (64 s). A conformant peer answers within milliseconds. A
  peer that never sends traffic restart allowed costs the whole timer: lower
  the two for it.
- A node now sends management messages on its linksets (transfer-prohibited
  for what it routes through each adjacent point, traffic restart allowed),
  where it sent nothing before.
- What a failed link had sent and not seen acknowledged is counted in
  `sigtran_m2pa_discarded_total{reason="tx-lost-on-failure"}` only when the
  changeover could not establish that the far end has it (no acknowledgement,
  or one without a sequence number); what is sent again or confirmed is in
  `sigtran_mtp3_retrieved_total`. A message handed to a link that is out of
  service is buffered and diverted, no longer counted `tx-not-in-service`.
- `sigtran_linkset_available` is `1` while level 3 routes traffic to a link of
  the linkset, which is later than level 2 being in service.
- The link of a linkset is chosen by a fixed assignment of selection codes to
  links, and falls back to the links that carry traffic. It used to be the
  code modulo the number of links in service, which moved every code when one
  link failed.
- The route state is recomputed when a link's availability changes, no longer
  after every message a link receives.

### Fixed

- **A listening association took whoever connected.** A second SCTP connection
  to the port of an association with an active ASP, sending nothing at all,
  was installed as the association: on SUA it received the next CLDT for the
  application server, on M3UA the ASP went down and its traffic stopped, on
  M2PA the link was taken out of service and aligned with the newcomer. See
  the two entries above: the peer is configured, and the first is not
  displaced. `tests/wire_identity.rs` has each on the wire.
- **A `client` association whose peer was absent at start stopped the node or
  was never dialled.** The start connected the client associations one after
  the other and waited for each: a refused connect failed the whole start and
  took the listening associations down with it, and a connect that did not
  return (see `async-sctp` above) kept that association and every one after
  it in the file from starting, with the dialogue and origination seams never
  attached. Neither was dialled when its far end appeared.
- **A `client` association that was lost was not established again**, so a
  link or an ASP of this node stayed down until the process was restarted.
  `tests/wire_reconnect.rs` has both on the wire.
- A listener that failed one `accept` stopped listening without a word. It
  logs the error and goes on.
- **An M2PA link did not stay in service against a conformant peer.** Every
  User Data message went out with BSN and FSN `0xFFFFFF`, and received ones were
  never acknowledged, so the far end saw each message after the first as out of
  sequence and ran into its T7 (RFC 4165 2.2, 4.2.1). User Data is now numbered
  from 0 after alignment, carries the FSN last received, and is acknowledged
  with an empty User Data message when nothing else is going out. Sent messages
  are kept until acknowledged, and one that stays unacknowledged for T7 fails
  the link.
- **The signalling link test was not answered**: a test message for this node
  was handed to SCCP routing and dropped, so a peer that tests its links took
  the link out after the second attempt.
- **A status the peer repeats took the link out of service** (a second
  Alignment, a third Ready), and there were no alignment or proving timers.
- All senders now hand an MSU for a linkset to the link's own task, which is the
  only writer of User Data on the association: the FSN order is the order on
  the stream.
- **A message that could not be routed was answered at SCCP level only.**
  Nothing told the adjacent point that sent it, which went on sending. It now
  gets a transfer-prohibited (Q.704 2.4.1, 13.2.2 iii), in addition to the SCCP
  return, and the message is counted
  (`sigtran_mtp3_discarded_total{reason="no-route"}`).
- **Route state changes were not announced** to adjacent signalling points.
- **A transfer-prohibited from a linkset was ignored**, as was every other
  management message for this node arriving on a link: service indicator 0
  was handed to SCCP routing and dropped.
- **Routes of equal priority did not share**: the first one listed carried
  everything.
- **A link that failed lost what it held.** Its unacknowledged and unsent
  messages were dropped and counted; they are now retrieved and sent on the
  alternative links.
- An adjacent point reached through a linkset of several links had one route
  per link, so the links counted as a combined linkset of themselves.

An M2PA link between this release and 4.1.0 or older does not come into
service: those do not answer the link test or acknowledge User Data. Upgrade both ends, or
set `link_test: { enabled: false }` and expect T7 to fail the link under
traffic.

Two nodes of this release that start at the same moment each wait `t18_ms` for
the other's traffic restart allowed, as Q.704 9.2.2 has a restarting node do.
In a lab, set `mtp3: { t18_ms: ... }` to what the wait is worth there.

## [4.1.0] — 2026-10-18

### Added

- **A script reads what the gsmSSF sends in a CAMEL call**, typed, where 3.0.0
  gave it the service key, the two called numbers and raw BER.
  - The rest of an InitialDP on `IncomingOp`: `imsi`, `calling_party_number`,
    `calling_partys_category`, `event_type_bcsm`, `subscriber_state` and
    `not_reachable_reason`, `location_information` (a `LocationInformation`
    with the VLR and MSC numbers, the cell global identity, the location area,
    the age), `ext_basic_service_code`, `call_reference_number`, `msc_address`,
    `time_and_timezone`, `call_forwarding_ss_pending`, and for a forwarded or
    terminating call `original_called_party_id`, `redirecting_party_id`,
    `redirection_information` and `gmsc_address`. They follow the getters there
    were: `None` for an absent member or another operation,
    `MistypedParameter` when the argument does not decode. The IMSI and the
    address strings are given as digits, and a string that holds something
    other than decimal digits is mistyped.
  - `component.event_report_bcsm`, an `EventReportBcsm`: the event type, the
    leg, whether the report is a request (the call waits for an instruction)
    or a notification, and the event specific information: the release, busy
    and failure causes, what an answer carries, the forwarding indications of
    a terminating busy or no-answer, `route_not_permitted` of an abandon.
  - `component.apply_charging_report`, an `ApplyChargingReport`: the party
    charged, the time used with or without a tariff switch, `leg_active`
    (`call_active` in phases 2 and 3), `call_leg_released_at_tcp_expiry`.
  - `dlg.application_context` (the arcs, a tuple) and `dlg.camel_phase` (1 to
    4), so a script can tell under which phase its dialogue runs.
- **A `MistypedParameter` raised by a view of one component carries
  `invoke_id`**, and the Reject the node sends for it names that component. A
  turn with several components (a charging report and the disconnect it belongs
  to) no longer has its first one rejected for the fault of another.

ApplyCharging for CAMEL phase 2 is still not typed: the phase 2 form of the
charging characteristics (GSM 09.78 clause 6.3, `releaseIfdurationExceeded [1]`
as a SEQUENCE holding the tone) has no type in `gsm_cap` 3. A script now sees
`dlg.camel_phase == 2` and can pass `charging_characteristics=`.

### Fixed

- **A message for a local subsystem that arrived in an XUDT was dropped**, so a
  dialogue opened that way was never answered and the peer waited for its own
  timer. Some networks send every message in an XUDT, whatever its size. An
  XUDT that holds a whole message (no segmentation parameter, or one that says
  first segment, none remaining) now reaches the dialogue engine as a UDT does
  (ITU-T Q.714 4.1), from M3UA, M2PA and SUA alike (a CLDT that carries a hop
  counter is such an XUDT).
- **The answer goes back in an XUDT** when the dialogue was opened in one,
  whole, protocol class 0, with a hop counter of 15. Q.714 leaves the choice
  between UDT and XUDT to the sender; the form the peer chose is one the path
  is known to carry. A dialogue the node opens still goes in a UDT.
- **The hop counter of an XUDT addressed by global title is checked before it is
  terminated** (Q.714 2.3.1): with one hop left the message is not delivered,
  it is counted in `sigtran_loops_detected_total{kind="hop-counter"}` and
  returned in an XUDTS, hop counter violation, when it asked to be returned. An
  XUDT addressed by subsystem number is not translated and is delivered
  whatever its hop counter says.
- **A `Begin` refused by the admission policy in a whole XUDT is aborted** with
  the P-Abort "resource limitation" in an XUDT, as one in a UDT is. It was
  discarded.

Reassembly is still not implemented: a segment of a segmented XUDT, and an
LUDT, are counted in `sigtran_rx_discarded_total{reason="not-unitdata"}` and
logged as before, and the message is not answered, not with an XUDTS either. An
answer that does not fit one message is not segmented.

## [4.0.0] — 2026-10-16

### Changed

- **`sigtran.yaml` is parsed by `serde-saphyr`** (YAML 1.2, safe Rust) instead
  of the deprecated `serde_yaml`, which sat on the unmaintained c2rust
  `unsafe-libyaml` (RUSTSEC-2024-0449). Breaking for Rust callers that match on
  it: `Error::Yaml` is now `Error::Yaml { path, source }`, the key path
  (`sccp.gtt[0].to.dpc`) and a boxed `serde_saphyr::Error`, and its message gives the
  path, the line and column, and a snippet of the offending line. Every config that loaded before loads to the same `Config`. Booleans
  stay `true` / `false` only (`screen: yes` is still refused), and duplicate keys
  and a second YAML document are still refused. Some inputs that were refused
  now load: a quoted number for a numeric field (`point_code: "1000"`), `1_000`,
  a `~` list read as empty, `<<` merge keys, a leading byte-order mark, and an
  unquoted `::1` in a flow list. Script-supplied values (`configure(dict)`,
  `ss7.gtt.add`, `ss7.content.add_rule`) go through the same parser, so an
  integer given for a string field (`gt_prefix=1555`) is now taken as its digits.

### Fixed

- `ss7.routes.cache` no longer fails on a global title holding a `"`: the value
  was pasted into YAML unescaped.

## [3.1.0] — 2026-10-16

### Added

- **An admission policy for new TCAP dialogues** (`admission` module,
  `Router::with_admission_policy` / `set_admission_policy`,
  `python::task_with_admission`). The embedding binary hands the router a Rust
  function that sees each TCAP `Begin` and `Unidirectional` the node relays or
  terminates and admits or refuses it; `Continue`, `End`, `Abort` and non-TCAP
  traffic always pass. A refused message the node relays follows the SCCP
  message return procedure (Q.714 4.2): a UDTS / XUDTS / LUDTS with return
  cause "unqualified" by default when it asked to be returned on error, a
  discard otherwise. A refused `Begin` for a local subsystem is answered with a
  P-Abort "resource limitation". Counted in
  `sigtran_admission_refused_total{reason,action}`. No policy set, no change.

## [3.0.0] — 2026-10-10

### Added

- **`sigtran_rx_discarded_total{reason}`**, and `metrics::RxDiscard` /
  `rx_discard` / `rx_discards` behind it: every message an association receives
  and drops before routing is counted, with a line on stderr that names the
  association and says why.

### Changed

- Moved to `gsm_map` 3 and `gsm_cap` 3, which depend on `tcap` 2 and `inap` 2.
  The dependency graph now holds one `tcap` and one `inap`; 2.0.0 carried
  both majors of each. No emitted octet and no public item changes.
- **`siphon.metrics()` is now `ss7.metrics()`** (breaking for a script that
  called it). `python::register` put a function named `metrics` on the `siphon`
  module, where `metrics` is the host's own namespace, and it ran after the host
  had filled the module: every script doing `from siphon import metrics;
  metrics.counter(...)` failed at import in a binary that called `register`. The
  node's Prometheus text is now a method of the addon's `ss7` namespace, so it is
  also there for a binary that mounts the namespaces one by one. `node.metrics()`
  is unchanged.

### Fixed

- **A global title with an even number of digits lost its last digit on the
  wire.** Every title the node built (`gsm_map.begin` / `gsm_cap.begin` /
  `inap.begin`, `node.originate`, `ss7.gt()`) and every title a content rule
  rewrote with `rewrite_cdpa_gt` went out with the odd/even indication it was
  constructed or received with, not the one its digits have, so a title of ten or
  twelve digits was marked odd and the next node read it one digit short
  (ITU-T Q.713 3.4.2.3). The fault and the fix are in the `sccp` codec, 1.1.1:
  the indication follows the digit count, and the filler after an odd count is
  `0000`.
- **A received title with an odd number of digits gained a trailing `0`** when
  the peer wrote the filler as Q.713 has it, so global title translation and
  content rules matched on a digit that was never sent. Fixed by the same `sccp`
  release, which reads the title by its odd/even indication.

A node on this release and a node on 2.0.0 disagree about an odd title by that
one `0`, in the direction of the older node.
- **A received message was dropped without a count or a log line** in these
  cases: a payload protocol identifier that is not the adaptation layer's, octets
  that do not decode (M3UA, SUA, M2PA), DATA or a CLDT from an ASP that is not
  active (RFC 4666 4.3.4.3) or user data on a link that is not in service, an
  M3UA DATA without Protocol Data (RFC 4666 3.3.1), and an MSU for a local
  subsystem that is not a UDT (an XUDT or LUDT among them: the dialogue engine
  reads only a UDT). None of them is answered yet; all of them now show.
- **An End or an Abort for a transaction that is not open** was counted
  (`sigtran_tcap_discarded_total{reason="unknown-transaction"}`) and not logged.
  It is the answer that arrives after an invoke timer has ended the dialogue, so
  the line names the transaction.

A test now runs two nodes of this crate against each other over kernel SCTP:
the ASP side begins and the SG side ends, then the reverse, twice each.
- **`variant: itu` did not load.** The reference, the quickstart and every
  cookbook write the variant in lower case, like every other keyword of
  `sigtran.yaml`, and the file was refused with ``unknown variant `itu`, expected
  one of `ITU`, `ANSI`, `CHINA` ``. The variant is now read whatever its letter
  case, so a file that says `ITU` loads as before.
- **`python::register` no longer replaces a name the host owns.** A test plants
  every built-in namespace name of the host on the module before `register` and
  requires each to be the same object afterwards.

## [2.0.0] — 2026-10-10

A major release: public items of the dialogue engine change type, and the
Python layer changes with them. The engine moves to `tcap` 2, whose decoder no
longer returns a message that lost part of itself, and with that this crate stops
doing three things that were wrong on the wire.

**What was wrong in 1.0.0**

- **Every Abort the node sent was malformed.** It was built as an opaque value
  under the P-Abort tag (`6A` around an `EXTERNAL`), which no peer reads: neither
  a P-Abort cause nor user abort information. That covered every abort there was:
  no handler for the operation, the dialogue ceiling, a handler that answered
  nothing, an invoke timer, an idle timer.
- **A damaged or unexpected message was dropped without the answer ITU-T Q.774
  requires.** A message that failed to decode was discarded in silence, whatever
  was wrong with it. A `Continue` for a transaction the node did not know was
  discarded too. And a message whose last component was malformed was not even
  seen as damaged: it was processed without that component.
- **A reply without a result parameter was not a valid ReturnResult.**
  `dlg.reply(...)` with a result that carries no parameter
  (`mo_forward_sm_res()`, `mt_forward_sm_res()`) went out with a result sequence
  holding the operation code alone (`30 03 02 01 2E`), which Q.773 does not
  have: the sequence is there with its parameter or not at all. And the send
  path swallowed encode errors, so the day the encoder refused that (it does in
  `tcap` 2) the reply would have vanished without a trace.

### Fixed

- **Damaged messages are answered** as Q.774 3.2.2 and 3.3.4 lay down. A fault in
  the transaction portion of a `Begin`, a `Continue` or a message of unknown type
  whose originating transaction ID can be read gets an Abort with the P-Abort
  cause. A fault in the dialogue portion gets an Abort carrying an ABRT APDU,
  abort-source dialogue-service-provider. A fault in a component gets a `Reject`
  component: the components before it are delivered as a normal turn, those after
  it are discarded, and the Reject leaves with the next `Continue` or `End` of the
  dialogue. Where Q.774 calls for no response (a damaged `End` or `Abort`, an
  originating transaction ID that cannot be read) there is none, and the message
  is counted in `sigtran_tcap_discarded_total`.
- **A `Continue` for an unknown transaction ID** is answered with a P-Abort,
  cause unrecognized transaction ID, addressed to its originating transaction ID
  (Q.774 Table 7). An `End` or an `Abort` for one is discarded.
- **Aborts are well-formed and say what they are.** The dialogue ceiling is a
  P-Abort, cause resource limitation. Everything the node aborts on behalf of the
  dialogue's user (no handler for the operation, a handler that answers nothing to
  a `Begin`, a class 1 invoke that got no reply, an idle dialogue, `dlg.abort()`)
  is a U-Abort: with an ABRT APDU, abort-source dialogue-service-user, when the
  dialogue was opened with an application context, and with no reason otherwise.
  An AARQ that does not list version 1 of the dialogue portion is refused with the
  AARE of Q.774 3.2.3.
- **A reply without a result parameter is a `ReturnResult` with no result
  sequence.**
- **Nothing on the send path fails silently.** A message the encoder refuses is
  logged at error level with the dialogue's transaction ids, counted in
  `sigtran_tcap_send_errors_total`, and returned to the caller (`Dialogue::send` /
  `end` / `abort` and `DialogueEngine::begin` return a `Result`). When it leaves a
  `Begin` unanswered the dialogue is aborted, so the peer is told.
- **A `Reject` from the peer reaches the handler as a Reject**: the invoke id,
  which may be absent, and the typed problem. It used to arrive as an error with
  code -1.
- **Invoke timers follow the operation class** (Q.774 3.2.1.1.3). The expiry of a
  timer is reported to the handler and is never an abort by the engine: for a
  class 1 operation it is an abnormal situation the handler decides on (the
  default aborts), for class 2 and 3 it is the normal outcome, class 4 just
  returns to idle. Every invoke used to be treated as class 1 and its timer
  aborted the dialogue, so an SCP that armed a detection point lost its dialogue
  after 15 seconds.
- **A handler that says nothing on a follow-up turn keeps the dialogue open.** It
  used to be aborted. (Saying nothing to a `Begin` still aborts it.)
- **The idle timeout is per dialogue** (`Dialogue::set_idle_timeout`,
  `dlg.set_idle_timeout(seconds)`), and `tcap.dialogue_timer_ms: 0` disables the
  default.
- **The handler is told when a dialogue ends, once, and why**
  (`TerminationHandler::on_closed`): a peer abort (P-Abort with its cause, or the
  kind of U-Abort), a damaged message, a timer. A peer abort or a timer used to
  remove the dialogue without a word, leaving whatever the handler had tied to it.
- **Every component of a `Begin` reaches the handler** (`IncomingOp::further`,
  `arg.further`). Only the first Invoke used to be looked at.
- **A result or an error that fits no operation in progress is rejected** (Q.774
  Table 5): an invoke id that names none of our invokes, a result for a class 2 or
  4 operation, an error for a class 3 or 4 operation, a linked id that is not an
  active invoke. They used to be delivered as if valid.
- **Nothing is sent after the peer's `End`.** A handler that staged components on
  the turn that carried the `End` had them sent to a transaction that no longer
  existed.
- **A MAP argument that does not decode is a mistyped parameter, not a missing
  field.** On `gsm_map` 2 every MAP decode goes through its strict decoder. The
  forward-SM getters (`arg.sm_rp_oa` / `sm_rp_da` / `sm_rp_ui`) returned `None`
  for an argument with a member that could not be read; they raise
  `siphon.MistypedParameter`, and a handler that lets it propagate has the Invoke
  rejected (Reject, invokeProblem mistypedParameter) in an End. The opposite
  defect is gone too: an argument carrying a member of a later release after an
  extension marker used to fail as a whole, and is now read (TS 29.002 17.1.4).
- **An IMSI rule is not skipped because the IMSI could not be read.** The content
  layer took a failed decode of the operation argument for "no IMSI", so the rule
  did not match and the message went on to the next rule or to GTT. The IMSI is
  now unknown rather than absent, the rule cannot be evaluated, and the message is
  dropped (`Action::Unevaluable`, counted as a hit of that rule with
  `action="unevaluable"`). `gsm_map` models the version 3 arguments only: the
  version 1 and 2 forms of cancelLocation, purgeMS and sendAuthenticationInfo do
  not decode, so an IMSI rule on those operations now drops them where it used to
  miss them.
- **The INAP application context was a module identifier.**
  `inap.AC.ssp_to_scp` was `0.4.0.1.1.0.3.0`, the object identifier of the ASN.1
  module `Core-INAP-CS1-Codes`. A dialogue the node opened with it named no
  application context an SSF knows. It is `0.4.0.1.1.1.0.0` (cs1-ssp-to-scp, ETS
  300 374-1 clause 6.5) on `inap` 2. Terminated dialogues were not affected:
  handlers are found by subsystem and operation, and the answer carries the
  context the peer proposed.
- **INAP encodings that a conforming SSF rejects are gone.** A leg in
  RequestReportBCSMEvent went out as a primitive `[2]` (`82 01 02`) where `legID`
  is an explicit tag around a CHOICE (`A2 03 80 01 02`); `informationToSend` and
  `collectedInfo` went out as opaque octets behind a primitive tag where both are
  constructed choices. See the `inap` 2.0.0 changelog for the full list.
- **An INAP InitialDP that does not decode is a mistyped parameter.** The
  `inap_service_key` / `inap_called_party_number` / `inap_calling_party_number`
  getters returned `None`; they raise `siphon.MistypedParameter`, answered with a
  Reject as for MAP. An InitialDP carrying the members a real SSF sends
  (`bearerCapability`, `extensions`, `redirectionInformation`, …) used to be
  refused as a whole, and decodes.
- **CAP encodings that a conforming gsmSSF rejects are gone**, on `gsm_cap` 2.
  `partyToCharge` in ApplyCharging went out as a primitive `[2]` where it is an
  explicit tag around `sendingSideID` (`A2 03 80 01 01`); a leg could not be
  given in RequestReportBCSMEvent at all, though a disconnect event needs one;
  Connect had its optional members on the wrong tags. See the `gsm_cap` 2.0.0
  changelog for the full list, which also covers what this crate decodes: an
  InitialDP as real equipment sends it (`bearerCapability`, `subscriberState`,
  `locationInformation` with a cell id, …) used to be refused as a whole.
- **ApplyCharging is encoded for the CAMEL phase of its dialogue.** The charging
  characteristics of phase 3 and phase 4 are different octets. The typed
  `gsm_cap.apply_charging(...)` is encoded when it is staged on a dialogue, from
  the dialogue's application context, and is not sent at all (nor is the rest of
  that turn's answer) when the context is neither.
- **A CAP InitialDP that does not decode is a mistyped parameter.**
  `arg.called_party_number` returned `None`; it raises `siphon.MistypedParameter`,
  answered with a Reject as for MAP and INAP.
- **A turn whose answer cannot be staged in full is not sent in part.** When one
  of the commands a Python handler staged fails, the ones staged before it in the
  same flush are dropped with it.
- **The MAP results and arguments the builders stage have the encodings `gsm_map`
  2 corrected.** `send_authentication_info_res` now carries the `[3]` tag of
  `SendAuthenticationInfoRes`; it went out as a bare SEQUENCE, which is the
  version 2 type. See the `gsm_map` 2.0.0 changelog for the full list.
- **Content rules no longer evaluate a message they could not read in full.** A
  `Begin` or `Continue` that does not decode completely is dropped in a domain
  with content rules and counted in `sigtran_content_unscreened_total`. Before, a
  message with a malformed last component was matched on its other components,
  and one that failed to decode outright was routed on unseen. Segments of a
  segmented XUDT / LUDT are still not evaluated (the node does not reassemble in
  transit); they are now counted, in the same family.

### Changed

- `tcap` 2 (was 1), `gsm_map` 2 (was 1.1), `inap` 2 (was 1.1), `gsm_cap` 2 (was
  1.2). `gsm_map` 2.0.0 still depends on `tcap` 1 and `gsm_cap` 2.0.0 on `inap`
  1, so the graph holds two versions of each until those are released against
  the new majors; no type of one version crosses to the other in this crate.
- `content::MapView` has `imsi_unreadable`; `content::Action` has `Unevaluable`.
- A Python handler that raises has what it staged before the exception discarded
  (an `async def` handler used to have it sent).
- `dialogue::Dialogue`: `invoke` returns `Result<InvokeId, DialogueError>`;
  `send`, `end` and `abort` return `Result<(), DialogueError>`; `abort` takes no
  argument (a handler aborts as the TC-user and cannot claim to be the provider);
  invoke ids are `i8` (`InvokeIdType ::= INTEGER (-128..127)`), allocated in a ring
  over 0..=127 that skips ids still in progress.
- `dialogue::PeerComponent` is `#[non_exhaustive]` and has `Reject` and
  `LocalReject`; its invoke ids are `i8`. `dialogue::IncomingOp` has `further` and
  an `i8` invoke id.
- `DialogueEngine::begin` returns `Result<(Tid, Vec<Msu>), DialogueError>`.
- `DialogueEngine::sweep` returns whatever the handlers flushed on a timer, not
  only aborts.
- `routing::Inbound` has `content_undecodable`.
- `sigtran_abort_total{source}` keeps its three values with a corrected meaning:
  `user` is a U-Abort from the peer's TC-user, `provider` a P-Abort or an ABRT /
  refusing AARE from the peer's TCAP, `local` an abort this node sent. A received
  Abort used to count as `provider` whatever it was.
- `sigtran_invoke_timeouts_total` counts class 1 expiries only.

### Added

- `dialogue::TerminationHandler::on_invoke_timeout` and `on_closed`;
  `OperationClass`, `InvokeTimeout`, `DialogueClosed`, `CloseReason`, `PeerAbort`,
  `UserAbort`, `DialogueError`; `Dialogue::invoke_with`, `reject`,
  `set_idle_timeout`, `idle_timeout`, `outstanding_invokes`.
- `content::screen` and `content::Screening`.
- `dialogue::PeerComponent::mistyped_parameter` and
  `IncomingOp::mistyped_parameter`: the invoke id and problem to `reject` a
  component with when its parameter does not decode.
- `dialogue::Dialogue::discard_staged`; `dialogue::DialogueError::Argument`.
- Python: `arg.service_key` and `arg.called_party_bcd_number` for a CAP
  InitialDP; `gsm_cap.AC.gsm_ssf_scf_phase4`; a leg in
  `gsm_cap.request_report_bcsm_event` events; the CAP event types 8, 16, 19, 27
  and 50 to 53; `original_called_party_id=` on `gsm_cap.connect`.
- Python: `siphon.MistypedParameter`; `inap.AC.assist_handoff_ssp_to_scp` and
  `inap.AC.ip_to_scp`; a leg in `inap.request_report_bcsm_event` events; INAP
  event types 1, 8 and 16.
- Metrics: `sigtran_tcap_abort_total{dir,kind,cause}` (`kind` is `p-abort` or
  `u-abort`; `cause` is a closed set, a P-Abort cause value Q.773 does not name
  counts as `other`), `sigtran_tcap_reject_total{dir,problem}`,
  `sigtran_tcap_discarded_total{reason}`, `sigtran_tcap_send_errors_total`,
  `sigtran_content_unscreened_total{reason,action}`.
- Tests: the abnormal procedures of Q.774 case by case (`tests/abnormal.rs`), with
  the damaged messages assembled by hand from Q.773 and every message the engine
  emits in response dissected by Wireshark, asserting on the fields it reads.

### What a script has to change

- **A Reject is no longer an error.** `turn.is_error` is false and
  `turn.error_code` is `None` for a `Reject`; test `turn.is_reject` and read
  `turn.reject_invoke_id`, `turn.reject_problem_class`, `turn.reject_problem_code`.
  A handler that aborted on `is_error` and should also give up on a rejected
  invoke needs `if turn.is_error or turn.is_reject`.
- **The handler is called for two things that are not messages.** A `PeerTurn`
  with `is_timeout` reports an invocation timer; one with `closed` set reports
  that the dialogue ended without the script ending it. Both have no components,
  so a handler that only tests `is_result` / `is_invoke` / `is_error` ignores them
  correctly. Use `closed` (and `is_end`) to release what the script tied to the
  dialogue.
- **`arg.sm_rp_oa` / `sm_rp_da` / `sm_rp_ui` raise `siphon.MistypedParameter`**
  for an argument that does not decode, and are `None` for any operation other
  than MO-ForwardSM (46) and MT-ForwardSM (44). A handler that tested them for
  `None` to detect a bad argument has to catch the exception, or let it propagate
  to have the Invoke rejected.
- **`gsm_cap.apply_charging` takes the charging as typed keywords**
  (`max_call_period_duration=` in units of 100 ms, `release_if_duration_exceeded=`,
  `tone=`, `tariff_switch_interval=`), and `party_to_charge=` is the leg number,
  not octets. `charging_characteristics=` still takes an already encoded value,
  which now has to be a CAMEL-AChBillingChargingCharacteristics value of the
  right phase for the gsmSSF to read it.
- **`gsm_cap.connect` takes exactly one destination**, as TS 29.078 has it.
- **`arg.called_party_number` raises `siphon.MistypedParameter`** for an InitialDP
  that does not decode, and is `None` for a mobile-originated call, which carries
  what was dialled in `arg.called_party_bcd_number`.
- **`inap.play_announcement` and `inap.prompt_and_collect_user_information` take
  typed arguments.** `information_to_send=` used to be opaque octets put on the
  wire as given; it is now the BER of an `InformationToSend` value and is refused
  if it is not one, and `message_id=` / `tone_id=` build the common cases.
  `collected_info=` likewise, with `maximum_digits=` for the common case.
- **`inap.AC.ssp_to_scp` has another value** (`0.4.0.1.1.1.0.0`). A script that
  compared an application context with the old arcs has to compare with the new.
- **The `inap_*` getters raise `siphon.MistypedParameter`** for an InitialDP that
  does not decode, and are `None` for any operation other than initialDP.
- **Saying nothing on a follow-up turn no longer aborts.** A handler that relied
  on that to get rid of a dialogue has to call `dlg.abort()` or `dlg.end()`.
- **Set an idle timeout on a dialogue that waits** (`dlg.set_idle_timeout(...)`):
  with its invoke timers no longer aborting it, a call-control dialogue now lives
  until `tcap.dialogue_timer_ms` of silence, 30 seconds by default.
- **`dlg.reply_to` and `dlg.error` raise `SigtranError`** for an invoke id outside
  -128..127 instead of putting it on the wire.
- **Nothing staged after the peer's `End` is sent.** `dlg.send()` / `dlg.end()` on
  a turn with `is_end` is logged as an error; drop the call.
- **`await gsm_map.begin(...)` raises `SigtranError`** saying why when the dialogue
  ends before an answer (a peer abort with its kind and cause, a timeout, a `Begin`
  that could not be encoded) instead of the one "closed with no response".
- New: `dlg.reject(invoke_id, problem_class, problem_code)`, `dlg.invoke(...,
  operation_class=, timeout=)`, `arg.further`, `turn.components`, the `Component`
  view, `node.sweep`, `node.assemble_tcap`, and `rejects` / `abort_kind` /
  `p_abort_cause` / `abort_source` / `result_invoke_id` on `node.decode(...)`.

## [1.0.0] — 2026-07-21

Initial release. A SIGTRAN/SS7 runtime that turns a declarative `sigtran.yaml`
into a running signalling node, plus a siphon addon for scripting it in Python.

### Transport

- **SCTP over M3UA (RFC 4666), M2PA (RFC 4165), and SUA (RFC 3868)**, on real
  kernel SCTP. M3UA runs the ASPSM/ASPTM handshake (ASP-UP, ASP-ACTIVE honouring
  the AS traffic mode of load-share / override / broadcast, ASP-INACTIVE/DOWN,
  BEAT); M2PA aligns links; SUA carries connectionless SCCP-user traffic
  (CLDT/CLDR) bridged one-for-one to SCCP so any-to-any interworking
  (SUA ↔ M3UA ↔ M2PA) falls out of the egress framing. SSNM (DUNA/DAVA → route
  state, DAUD answered from live state) folds into the router.

### Routing

- **MTP3 routing**: implicit adjacent routes, explicit routes by priority,
  availability from Pause/Resume/Status and linkset up/down, with failover.
- **SCCP GTT**: ordered prefix + gti/tt/np/nai matching, cost and weighted-share
  groups, local termination, and the E.214 → E.164 pre-step from a PLMN map.
- **Content routing** on the decoded MAP/CAP layer (operation, calling/called GT,
  IMSI/MSISDN), first-match, evaluated on the live wire: **route**, **rewrite the
  called-party GT**, or **screen**. The decode runs only for a tenant that has
  content rules, so a pure-transit node adds no per-message cost.
- **Loop guards** (own-OPC, route-reflect, SCCP hop-counter) and **SCCP
  return-on-error** (UDTS/XUDTS/LUDTS) on undeliverable connectionless messages.
- Optional **ISUP-aware screening** on the SI=5 transit path (block/allow rules
  on message type + called/calling prefix), counted under
  `sigtran_isup_screened_total`.

### Dialogue termination

- A synchronous **TCAP transaction engine** (Begin/Continue/End + AARQ/AARE):
  single request/response, held-open multi-leg (updateLocation with an
  insertSubscriberData leg), invoke and dialogue timers, a dialogue ceiling, and
  aborts. The TCAP + SCCP bytes are wire-real, built with the published codecs.

### The siphon addon (feature = "python")

- Two startup seams a composing siphon binary calls: `configure_from(cfg)` builds
  the node from its `extensions.sigtran` config, and `register(py, parent)` mounts
  the `ss7` / `gsm_map` / `gsm_cap` / `inap` namespaces.
- **Live table programming** from Python (`ss7.routes` / `ss7.gtt` / `ss7.content`),
  so routing is shaped from a script at load time while every per-message decision
  stays in Rust.
- **MAP/CAP/INAP termination** via one decorator per namespace,
  `@ns.on_operation("<name>")` (pipe-separated for several, bare for a catch-all),
  covering a full HLR, a terminating SMSC front end, and a CAMEL/INAP SCP; with the
  MAP result and invoke builders and the CAP/INAP invoke builders, driving a
  `Dialogue` handle that observes a decoded `PeerTurn` on held-open follow-up legs.
- An in-process test seam (`siphon.configure` → a `Node` that assembles genuine
  inbound MSUs and drives them through the dialogue engine off the wire).

### Observability

- The full Prometheus metric family (association / ASP / linkset state, route
  availability, MSU rate, GTT / content / MTP3-management counters, active
  dialogues, dialogue / invoke timeouts, aborts, loop guards, ISUP screening) with
  a text renderer.

### Not in this release (planned)

- **Per-message Python routing overrides** — dispatching a routing decision into a
  script hook on the live wire. Route from Python by programming the tables live
  instead; static content-rule actions (route / rewrite / screen) run in Rust.
- **Dialogue origination** — opening a dialogue the node initiates (an SMSC's MT
  delivery, an SMS-GMSC) and correlating the peer's response over SCTP. Termination
  of inbound dialogues is fully supported.

[1.0.0]: https://github.com/siphon-project/siphon-sigtran/releases/tag/v1.0.0
