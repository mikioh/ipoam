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


Show network facility information

Show displays network facility information.

Usage:	ipoam sh|show|list [flags] int|interfaces [interface name]

Flags:
	-4	Show IPv4 information only
	-6	Show IPv6 information only
	-b	Show brief information
*/
package main
