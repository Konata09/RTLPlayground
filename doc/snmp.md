# Read-only SNMPv2c

Build with `make MACHINE=<profile> SNMP=1`. Without SNMP=1 the agent is omitted.
Generic UDP validation, NIC RX bounds, endian handling and startup CRLF support
are unconditional. The generic UDP allocator stays in BANK1 in both configurations.

The agent starts disabled and unconfigured. There is no default community or
compile-time credential header. In **System → SNMP**, enter the allowed manager
IP/CIDR and a community, choose the agent state, then click **Apply**. Use `/32`
for one manager. The community accepts 1–32 printable ASCII characters without
spaces; leave it blank to retain an existing community. **Refresh** discards
unapplied edits. Protocol, access mode and UDP port are informational.

The authenticated console and UART provide the same settings:

```
snmp community <1-to-32-printable-ASCII-characters>
snmp manager 192.0.2.250/32
snmp on
snmp show
snmp off
```

Use your actual trusted manager address; the example is an RFC 5737 alias.
Manager prefixes 1–32 are accepted; host bits are normalized to the network.
Invalid input preserves current settings. Changes apply immediately but require
the existing **Save to Flash** confirmation to survive reboot. Save serializes
manager, community and on/off from runtime state, not stale command history.
No new Flash regions are used. Existing startup records restore the same state;
old `snmp changed` metadata is ignored during replay, rejected from live CLI,
and omitted from new saves. Configuration-change timestamps are not implemented.

The System page uses the normal settings rows, masked community input and
Apply/Refresh controls. Apply disables the agent before changing its ACL or
community and only enables it after all requested setters succeed. A failed
sequence stops and refreshes the actual runtime state; earlier changes may
already have taken effect. Save is unavailable while Apply is in progress.
Community values are masked in the configuration editor and Web Console, never
included in `snmp show` or `/information.json`. Startup Flash, UART history and
authenticated configuration HTTP responses still contain plaintext; browser
masking is not secret isolation. SNMPv2c and HTTP are unencrypted. Restrict
management access and set a narrow source ACL. A subnet ACL excludes network and
broadcast source addresses, except /31 and /32 point-to-point/host cases.

## Objects

GET, GETNEXT and GETBULK expose the following read-only objects:

- LLDP-MIB (`1.0.8802.1.1.2.1`): `lldpLocalSystemData` scalars
  (`lldpLocChassisIdSubtype`, `lldpLocChassisId`, `lldpLocSysName`,
  `lldpLocSysDesc`, `lldpLocSysCapSupported`, `lldpLocSysCapEnabled`),
  `lldpLocPortTable` (`lldpLocPortIdSubtype`, `lldpLocPortId`, `lldpLocPortDesc`),
  `lldpRemTable` (`lldpRemChassisIdSubtype`, `lldpRemChassisId`,
  `lldpRemPortIdSubtype`, `lldpRemPortId`, `lldpRemPortDesc`, `lldpRemSysName`,
  `lldpRemSysCapSupported`, `lldpRemSysCapEnabled`) and `lldpRemManAddrTable`
  (`lldpRemManAddrIfSubtype`, `lldpRemManAddrIfId`) for live IPv4 management
  addresses in `lldp_nb[]`.
- SNMPv2-MIB system: `sysDescr.0`, `sysObjectID.0` (`1.3.6.1.3.8373.1` or
  `1.3.6.1.3.8372.1` under experimental, borrowing no vendor PEN), `sysUpTime.0`,
  `sysContact.0` (empty), `sysName.0`, `sysLocation.0` (empty) and
  `sysServices.0` (2, layer-2 bridge/switch). `sysUpTime` is Counter32-width
  TimeTicks in centiseconds.
- IF-MIB: `ifNumber.0`; `ifTable` columns `ifIndex`, `ifDescr`, `ifType`,
  `ifMtu`, `ifSpeed`, `ifPhysAddress`, `ifAdminStatus`, `ifOperStatus`,
  `ifInOctets`, `ifInUcastPkts`, `ifInErrors`, `ifOutOctets`, `ifOutUcastPkts`
  and `ifOutErrors`.
- EtherLike-MIB (`1.3.6.1.2.1.10.7.2.1.19`): `dot3StatsDuplexStatus`
  (`unknown(1)` when link down, `halfDuplex(2)`, `fullDuplex(3)`).
- IF-MIB `ifXTable`: `ifName`, `ifInMulticastPkts`, `ifInBroadcastPkts`,
  `ifOutMulticastPkts`, `ifOutBroadcastPkts`, `ifHCInOctets`, `ifHCInUcastPkts`,
  `ifHCInMulticastPkts`, `ifHCInBroadcastPkts`, `ifHCOutOctets`,
  `ifHCOutUcastPkts`, `ifHCOutMulticastPkts`, `ifHCOutBroadcastPkts`,
  `ifHighSpeed`, `ifConnectorPresent` and `ifAlias`.
- ENTITY-MIB (`1.3.6.1.2.1.47.1.1.1.1`): `entPhysicalTable` columns `Descr`,
  `ContainedIn`, `Class`, `ParentRelPos`, `Name`, `HardwareRev`, `FirmwareRev`,
  `SerialNum`, `MfgName`, `ModelName` and `IsFRU` for Chassis (1), ASIC
  Temperature sensor (2), present SFP+ transceiver modules (10/20) and
  internally calibrated SFF-8472 DDM sensors (11..15 / 21..25).
- ENTITY-SENSOR-MIB (`1.3.6.1.2.1.99.1.1.1`): `entPhySensorTable` columns
  `Type`, `Scale`, `Precision`, `Value`, `OperStatus` and `UnitsDisplay` for
  ASIC die temperature (0.1 C) and internally calibrated SFP+ DDM sensors
  (Temperature in 0.1 C, Vcc in 0.0001 V, TxBias in uA, TxPower/RxPower in
  0.1 uW).

Octet/unicast ifTable counters use Counter32; native high-capacity counters use
Counter64. Speeds are Gauge32 (ifSpeed in bit/s, saturating at UINT32_MAX;
ifHighSpeed in Mbit/s). A down/unknown-speed port retains both speed rows with
zero values. Hardware read failures return genErr rather than fabricated zeros
(SFP I2C DDM read errors report `unavailable(2)` in `entPhySensorOperStatus`
and 0 in `entPhySensorValue` so a misbehaving module does not abort a full MIB
walk). Indices identify actual front-panel ports, including SFP, without a CPU
row. ifAdminStatus reads the copper PHY power-down bit, independently of link
state. SFP ports are administratively up because this firmware has no SFP
disable operation. ifAlias is the configured port name, or an empty string.
Error counters use the RX/TX 32-bit halves of hardware selector 48, not a
synthetic 64-bit extension. Discards are not exposed.
SET, SNMPv3, notifications and writable system strings are unsupported.
Requests are limited to 484 bytes, eight stored varbinds and 32 OID arcs.
Authenticated, well-formed requests with more than eight varbinds receive
tooBig with an empty list; malformed requests are still dropped.

GETBULK honours non-repeaters and max-repetitions, returning successive rows
in request order. Responses stop at the 484-byte message limit, so clients
must continue from the last returned OID. Negative request fields mean zero.
Output is not limited to eight varbinds. Net-SNMP `snmpwalk` and
`snmpbulkwalk -Cr25` can traverse the same implemented objects.

## Verification and limits

`make -C test` runs host subsystem, SNMP, transport, hardware-adapter, CLI and
startup replay tests with sanitizers. Use `CC=clang` for the other compiler.
Local JavaScript tests use `make -C test snmp-gui`; the optional browser test is
`node test/test_system_layout.cjs` with an available Playwright installation.
Firmware checks use SDCC 4.5.0, with per-bank map/memory inspection on both chip
families. Host register/Flash mocks do not establish hardware timing or stack
high-water. The bounded statistics adapter fails a timed-out request without
replacing pending commands. Later requests recover only after both the SFR
engine and statistics selector are idle; incomplete snapshots are never
returned. STAT_GET's unbounded waits are not substituted into a network
request path.
Runtime stack high-water remains unmeasured. Review image target/CRC, backups and
recovery separately before any hardware upgrade.


## Hardware validation scope

See [HORACO Full Candidate validation](validation/HORACO_SWTGW218AS-fullcandidate.md)
for image identity, completed physical Ethernet/basic SNMP/stress observations and
remaining acceptance gates. GETBULK, walk ordering and bounded fault recovery have
passing host tests; complete physical GETBULK/walk and forced-fault evidence is
still required. Static stack capacity is not measured runtime headroom. The
publication integration preserves the single **System → SNMP** configuration card.
Authenticated configuration export still contains the community for Save; visual
masking does not protect it from an authenticated browser or network observation.

## Upstream machine port API

Port enumeration uses the selected profile's `MACHINE_MIN_PORT` and
`MACHINE_MAX_PORT` ASIC MAC bounds, capped below `CPU_PORT`. The existing
`machine.log_to_phys_port` table maps each MAC slot to its front-panel ifIndex;
SNMP rows remain sorted by that index. Counts come from mapped rows, not
`MACHINE_MAX_PORT + 1`, and SFP rows use the existing `machine.is_sfp` metadata.
The hardware adapter uses `MACHINE_PORT_VALID` and separately excludes the CPU.
The removed runtime `machine.min_port/max_port` members are not used.

The 24 October upstream refresh changes only these SNMP bound expressions.
GET/GETNEXT/GETBULK encoding, response limits, authentication, source ACL,
configuration persistence and bounded hardware recovery retain their reviewed
logic. A new build is not byte-identical to the physically tested image; see
the validation document for the original artifact identity and outstanding
hardware acceptance requirements.
