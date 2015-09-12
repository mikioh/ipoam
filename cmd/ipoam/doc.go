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
	Connectivity verification for golang.org [64.233.188.141]: 56 bytes payload
	56 bytes hops=34 from=64.233.188.141 to=192.168.0.1 if=en1 echo.id=31002 echo.seq=1 rtt=153.178874ms
	56 bytes hops=34 from=64.233.188.141 to=192.168.0.1 if=en1 echo.id=31002 echo.seq=2 rtt=154.840432ms
	56 bytes hops=34 from=64.233.188.141 to=192.168.0.1 if=en1 echo.id=31002 echo.seq=3 rtt=154.94983ms

	Statistical information for golang.org:
	64.233.188.141: 0.0% loss, rcvd=3 sent=3 op.err=0 icmp.err=0 min=153.178874ms avg=154.323045ms max=154.94983ms stddev=810.346µs


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
	Warning: golang.org has multiple addresses, using 64.233.188.141
	  1  192.168.0.254 hops=255 to=192.168.0.1 if=en1  2.031923ms  1.403751ms  1.434872ms
	  2  *  1.005006451s  1.004994014s  1.002939936s
	[...]
	 15  72.14.204.58 hops=241 to=192.168.0.1 if=en1  73.578229ms  55.443889ms  49.584016ms
	 16  72.14.236.82 hops=240 to=192.168.0.1 if=en1  74.303434ms  59.903357ms
	     72.14.239.202 hops=240 to=192.168.0.1 if=en1  93.422118ms
	 17  209.85.255.34 hops=237 to=192.168.0.1 if=en1 <label=562784 tc=4 s=true ttl=1>  53.306689ms
	     209.85.255.36 hops=237 to=192.168.0.1 if=en1 <label=623536 tc=4 s=true ttl=1>  104.269461ms  51.352129ms
	 18  72.14.235.147 hops=234 to=192.168.0.1 if=en1 <label=748322 tc=4 s=true ttl=1>  107.216645ms  111.063542ms
	     209.85.249.53 hops=234 to=192.168.0.1 if=en1 <label=25248 tc=4 s=true ttl=1>  130.047646ms
	 19  66.249.94.131 hops=235 to=192.168.0.1 if=en1  126.817933ms
	     216.239.43.101 hops=235 to=192.168.0.1 if=en1  125.024893ms
	     216.239.50.45 hops=235 to=192.168.0.1 if=en1  149.717442ms
	 20  *  1.00502412s  1.00495912s  1.005002805s
	 21  tk-in-f141.1e100.net. (64.233.188.141) hops=35 to=192.168.0.1 if=en1  148.950998ms  150.973918ms  148.837758ms


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
