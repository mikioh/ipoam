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
	Connectivity verification for golang.org [216.58.220.177 2404:6800:4004:812::2011]: 56 bytes payload
	error="write ip6 ::->2404:6800:4004:812::2011: sendmsg: no route to host"
	56 bytes tc=0x0 hops=51 from=nrt13s35-in-f177.1e100.net. (216.58.220.177) to=blah.lan. (192.168.86.23) if=en0 echo.id=53048 echo.seq=1 rtt=8.997034ms
	error="write ip6 ::->2404:6800:4004:812::2011: sendmsg: no route to host"
	56 bytes tc=0x0 hops=51 from=nrt13s35-in-f177.1e100.net. (216.58.220.177) to=blah.lan. (192.168.86.23) if=en0 echo.id=53048 echo.seq=2 rtt=13.278403ms
	error="write ip6 ::->2404:6800:4004:812::2011: sendmsg: no route to host"
	56 bytes tc=0x0 hops=51 from=nrt13s35-in-f177.1e100.net. (216.58.220.177) to=blah.lan. (192.168.86.23) if=en0 echo.id=53048 echo.seq=3 rtt=18.912692ms

	Statistical information for golang.org:
	nrt13s35-in-f177.1e100.net. (216.58.220.177): loss=0.0% rcvd=3 sent=3 op.err=0 icmp.err=0 min=8.997034ms avg=13.729376ms max=18.912692ms stddev=4.060592ms
	nrt13s35-in-x11.1e100.net. (2404:6800:4004:812::2011): loss=100.0% rcvd=0 sent=3 op.err=3 icmp.err=0 min=0 avg=0 max=0 stddev=0


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
	  1  onhub.here. (192.168.86.1) tc=0xc0 hops=64 to=192.168.86.23 if=en0  11.039045ms  4.42153ms  1.338854ms
	 14  int-0-0-1-0.r1.sql1.isc.org. (149.20.65.10) tc=0x0 hops=242 to=192.168.86.23 if=en0  120.675621ms  123.244983ms
	     int-0-1-0-1.r1.pao1.isc.org. (149.20.65.22) tc=0x0 hops=241 to=192.168.86.23 if=en0 <label=289970 tc=0x0 s=true ttl=255>  118.908109ms
	 15  149.20.56.156 tc=0x0 hops=241 to=192.168.86.23 if=en0  119.487097ms
	     int-0-0-1-0.r1.sql1.isc.org. (149.20.65.10) tc=0x0 hops=242 to=192.168.86.23 if=en0  118.258953ms  119.722504ms
	 16  149.20.56.156 tc=0x0 hops=241 to=192.168.86.23 if=en0  117.149574ms
	     ix1.dns-oarc.net. (149.20.58.198) tc=0xc0 hops=49 to=192.168.86.23 if=en0  120.063393ms  117.426795ms


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
