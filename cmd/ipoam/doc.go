// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
IPOAM verifies IP-layer connectivity and discovers an IP-layer path
like ping and traceroute commands.

Usage:	ipoam command [flags] [arguments]

The commands are:
	cv|ping                 Verify IP-layer connectivity
	rt|pathdisc|traceroute  Discover an IP-layer path
	sh|show|list            Show network facility information


Verify IP-layer connectivity

CV (Connectivity Verification) uses both ICMP echo request and reply
messages for verifying IP-layer connectivity. The destination can be
unicast (including anycast), multicast or broadcast addresses.
Also it can be a single or multiple addresses.

Usage:	ipoam cv|ping [flags] destination

destination
	A hostname, DNS reg-name, IP address, IP address prefix, or
	comma-separated list of IP addresses and/or IP address prefixes.
	A combination of unicast and multicast addresses is prohibited.

Flags:
	-4	Run IPv4 test only
	-6	Run IPv6 test only
	-count int
		Iteration count, less than or equal to zero will run until interruped
	-hops int
		IPv4 TTL or IPv6 hop-limit on outgoing unicast packets (default 64)
	-if string
		Outbound interface name
	-mchops int
		IPv4 TTL or IPv6 hop-limit on outgoing multicast packets (default 5)
	-n	Don't use DNS reverse lookup
	-pldlen int
		ICMP echo payload length (default 56)
	-q	Quiet output except summary
	-src string
		Source IP address
	-tc int
		IPv4 TOS or IPv6 traffic-class on outgoing packets
	-v	Show verbose information
	-wait int
		Seconds between transmitting each echo (default 1)
	-x	Run transmission only

A sample output:

	% sudo ipoam cv -v -4 -count=3 golang.org
	Connectivity verification for golang.org [74.125.203.141]: 56 bytes payload
	56 bytes tc=0x0 hops=46 from=th-in-f141.1e100.net. (74.125.203.141) to=192.168.0.1 if=en0 echo.id=17278 echo.seq=1 rtt=44.323195ms
	56 bytes tc=0x0 hops=46 from=th-in-f141.1e100.net. (74.125.203.141) to=192.168.0.1 if=en0 echo.id=17278 echo.seq=2 rtt=43.952098ms
	56 bytes tc=0x0 hops=46 from=th-in-f141.1e100.net. (74.125.203.141) to=192.168.0.1 if=en0 echo.id=17278 echo.seq=3 rtt=40.670227ms

	Statistical information for golang.org:
	th-in-f141.1e100.net. (74.125.203.141): 0.0% loss, rcvd=3 sent=3 op.err=0 icmp.err=0 min=40.670227ms avg=42.98184ms max=44.323195ms stddev=1.641563ms

Discover an IP-layer path

RT (Route Tracing) transmits probe packets and discovers a route to
the destination by determining received ICMP error messages from nodes
along the route. The probe packets can be carried by either UDP or
ICMP.

Usage:	ipoam rt|pathdisc|traceroute [flags] destination

destination
	A hostname, DNS reg-name or IP address.

Flags:
	-4	Run IPv4 test only
	-6	Run IPv6 test only
	-count int
		Per-hop probe count (default 3)
	-hops int
		Maximum IPv4 TTL or IPv6 hop-limit (default 30)
	-if string
		Outbound interface name
	-m	Use ICMP for probe packets instead of UDP
	-n	Don't use DNS reverse lookup
	-pldlen int
		Probe packet payload length (default 56)
	-port int
		Base destination port number, range will be [port, port+hops) (default 33434)
	-src string
		Source IP address
	-tc int
		IPv4 TOS or IPv6 traffic-class on probe packets
	-v	Show verbose information
	-wait int
		Seconds between transmitting each probe (default 1)

A sample output:

	% sudo ipoam rt -v golang.org
	Path discovery for golang.org: 30 hops max, 3 per-hop probes, 56 bytes payload
	Warning: golang.org has multiple addresses, using 173.194.72.141
	  1  192.168.0.254 tc=0x0 hops=255 to=192.168.0.1 if=en1  6.881108ms  1.259877ms  1.216255ms
	  2  *  1.002800195s  1.004971212s  1.001800509s
	[...]
	  6  72.14.204.58 tc=0x0 hops=250 to=192.168.0.1 if=en0  8.187242ms  7.70626ms  8.196697ms
	  7  72.14.236.82 tc=0x0 hops=249 to=192.168.0.1 if=en0  8.107614ms
	     72.14.239.202 tc=0x0 hops=249 to=192.168.0.1 if=en0  8.463247ms  8.128451ms
	  8  72.14.239.55 tc=0x0 hops=244 to=192.168.0.1 if=en0 <label=29135 tc=0x4 s=true ttl=1>  44.717919ms
	     209.85.255.34 tc=0x0 hops=246 to=192.168.0.1 if=en0 <label=347078 tc=0x4 s=true ttl=1>  12.061771ms  34.364548ms
	  9  72.14.232.129 tc=0x0 hops=245 to=192.168.0.1 if=en0 <label=24699 tc=0x4 s=true ttl=1>  41.402896ms
	     209.85.248.129 tc=0x0 hops=245 to=192.168.0.1 if=en0 <label=24371 tc=0x4 s=true ttl=1>  42.836363ms
	     209.85.249.53 tc=0x0 hops=245 to=192.168.0.1 if=en0 <label=25941 tc=0x4 s=true ttl=1>  42.692689ms
	 10  72.14.235.71 tc=0x0 hops=246 to=192.168.0.1 if=en0  41.671242ms  41.603505ms
	     72.14.235.77 tc=0x0 hops=246 to=192.168.0.1 if=en0  49.409008ms
	 11  *  1.003972178s  1.004476507s  1.003024307s
	 12  th-in-f141.1e100.net. (74.125.203.141) tc=0x0 hops=46 to=192.168.0.1 if=en0  44.859789ms  42.72805ms  42.288866ms


Show network facility information

Show displays network facility information.

Usage:	ipoam sh|show|list [flags] int|interfaces [interface name]

Flags:
	-4	Show IPv4 information only
	-6	Show IPv6 information only
	-b	Show brief information

A sample output:

	% ipoam sh -b int
	Name              Index  Status  Routed      MTU    Hardware address
	lo0               1      up      link-local  16384  <nil>
	gif0              2      down                1280   <nil>
	stf0              3      down                1280   <nil>
	en0               4      up                  1500   00:01:02:ab:cd:01
	en1               5      up      global      1500   00:01:02:ab:cd:02
	fw0               6      up                  4078   00:01:02:03:ab:cd:ef:01
	p2p0              7      up                  2304   00:01:02:ab:cd:03
*/
package main
