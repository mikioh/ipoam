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
	Connectivity verification for golang.org [173.194.72.141]: 56 bytes payload
	56 bytes tc=0x0 hops=36 from=173.194.72.141 to=192.168.0.1 if=en1 echo.id=46383 echo.seq=1 rtt=162.508918ms
	56 bytes tc=0x0 hops=36 from=173.194.72.141 to=192.168.0.1 if=en1 echo.id=46383 echo.seq=2 rtt=157.233688ms
	56 bytes tc=0x0 hops=36 from=173.194.72.141 to=192.168.0.1 if=en1 echo.id=46383 echo.seq=3 rtt=160.959004ms

	Statistical information for golang.org:
	173.194.72.141: 0.0% loss, rcvd=3 sent=3 op.err=0 icmp.err=0 min=157.233688ms avg=160.23387ms max=162.508918ms stddev=2.213801ms


Discover an IP-layer path

RT (Route Trace) transmits probe packets and discovers a route to the
destination by determining recevived ICMP error messages from nodes
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
	 15  72.14.204.58 tc=0x0 hops=241 to=192.168.0.1 if=en1  94.682646ms  94.999308ms  81.693418ms
	 16  72.14.239.202 tc=0x0 hops=240 to=192.168.0.1 if=en1  105.799675ms  94.859865ms  94.828963ms
	 17  66.249.94.80 tc=0x0 hops=233 to=192.168.0.1 if=en1 <label=28257 tc=0x4 s=true ttl=1>  149.924191ms
	     209.85.245.206 tc=0x0 hops=233 to=192.168.0.1 if=en1 <label=32722 tc=0x4 s=true ttl=1>  154.502803ms  150.42802ms
	 18  72.14.233.137 tc=0x0 hops=234 to=192.168.0.1 if=en1 <label=693726 tc=0x4 s=true ttl=1>  164.885999ms
	     72.14.235.147 tc=0x0 hops=234 to=192.168.0.1 if=en1 <label=453203 tc=0x4 s=true ttl=1>  154.552519ms
	     209.85.248.129 tc=0x0 hops=234 to=192.168.0.1 if=en1 <label=24431 tc=0x4 s=true ttl=1>  154.920485ms
	 19  72.14.237.171 tc=0x0 hops=235 to=192.168.0.1 if=en1  170.145454ms
	     209.85.243.21 tc=0x0 hops=235 to=192.168.0.1 if=en1  118.445733ms  154.649823ms
	 20  *  1.000688625s  1.000789355s  1.001540175s
	 21  tf-in-f141.1e100.net. (173.194.72.141) tc=0x0 hops=37 to=192.168.0.1 if=en1  161.714887ms  154.699088ms  139.969393ms


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
