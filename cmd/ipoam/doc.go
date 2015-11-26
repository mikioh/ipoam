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

	% sudo ipoam cv -v -count=3 golang.org
	Connectivity verification for golang.org [216.58.220.241 2404:6800:4004:814::2011]: 56 bytes payload
	56 bytes tc=0x0 hops=56 from=nrt13s37-in-f17.1e100.net. (216.58.220.241) to=192.168.0.3 if=en0 echo.id=30896 echo.seq=1 rtt=44.303633ms
	56 bytes tc=0x0 hops=56 from=nrt13s37-in-x11.1e100.net. (2404:6800:4004:814::2011) to=240f:6d:3e21:1:9c02:d0d6:e40d:5341 if=en0 echo.id=30896 echo.seq=1 rtt=46.89151ms
	56 bytes tc=0x0 hops=56 from=nrt13s37-in-f17.1e100.net. (216.58.220.241) to=192.168.0.3 if=en0 echo.id=30896 echo.seq=2 rtt=17.458021ms
	56 bytes tc=0x0 hops=56 from=nrt13s37-in-x11.1e100.net. (2404:6800:4004:814::2011) to=240f:6d:3e21:1:9c02:d0d6:e40d:5341 if=en0 echo.id=30896 echo.seq=2 rtt=18.313848ms
	56 bytes tc=0x0 hops=56 from=nrt13s37-in-f17.1e100.net. (216.58.220.241) to=192.168.0.3 if=en0 echo.id=30896 echo.seq=3 rtt=15.882498ms
	56 bytes tc=0x0 hops=56 from=nrt13s37-in-x11.1e100.net. (2404:6800:4004:814::2011) to=240f:6d:3e21:1:9c02:d0d6:e40d:5341 if=en0 echo.id=30896 echo.seq=3 rtt=36.196468ms

	Statistical information for golang.org:
	nrt13s37-in-f17.1e100.net. (216.58.220.241): loss=0.0% rcvd=3 sent=3 op.err=0 icmp.err=0 min=15.882498ms avg=25.881384ms max=44.303633ms stddev=13.042367ms
	nrt13s37-in-x11.1e100.net. (2404:6800:4004:814::2011): loss=0.0% rcvd=3 sent=3 op.err=0 icmp.err=0 min=18.313848ms avg=33.800608ms max=46.89151ms stddev=11.789143ms


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

	% sudo ipoam rt -v www.as112.net
	Path discovery for www.as112.net: 30 hops max, 3 per-hop probes, 56 bytes payload
	Warning: www.as112.net has multiple addresses, using 149.20.58.198
	  1  192.168.0.1 tc=0x0 hops=255 to=192.168.0.3 if=en0  7.715428ms  1.882559ms  1.349216ms
	[...]
	  7  ae1.mpr2.pao1.us.zip.zayo.com. (64.125.14.33) tc=0x0 hops=247 to=192.168.0.3 if=en0  113.875371ms  117.308859ms  120.627108ms
	  8  64.125.25.165 tc=0x0 hops=246 to=192.168.0.3 if=en0  137.852291ms  126.503729ms  138.970751ms
	  9  isc-above-oc3.pao.isc.org. (216.200.0.10) tc=0x0 hops=247 to=192.168.0.3 if=en0  124.94996ms  117.130496ms  115.594481ms
	 10  int-0-1-0-0.r1.pao1.isc.org. (149.20.65.20) tc=0x0 hops=246 to=192.168.0.3 if=en0 <label=289970 tc=0x0 s=true ttl=255>  184.430375ms  172.277626ms
	     149.20.65.22 tc=0x0 hops=246 to=192.168.0.3 if=en0 <label=289970 tc=0x0 s=true ttl=255>  123.429594ms
	 11  int-0-0-1-0.r1.sql1.isc.org. (149.20.65.10) tc=0x0 hops=247 to=192.168.0.3 if=en0  161.092584ms  146.05843ms  119.608538ms
	 12  149.20.56.156 tc=0x0 hops=246 to=192.168.0.3 if=en0  142.293248ms  121.059763ms  118.12153ms
	 13  ix1.dns-oarc.net. (149.20.58.198) tc=0x0 hops=54 to=192.168.0.3 if=en0  117.361415ms  130.268473ms  119.191445ms


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
