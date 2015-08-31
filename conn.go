// Copyright 2014 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipoam

import (
	"fmt"
	"net"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	// See golang.org/x/net/internal/iana.
	ianaProtocolIP       = 0
	ianaProtocolICMP     = 1
	ianaProtocolUDP      = 17
	ianaProtocolIPv6     = 41
	ianaProtocolIPv6ICMP = 58
)

// A conn represents a connection endpoint.
type conn struct {
	protocol  int            // protocol number
	rawSocket bool           // true if c is a raw socket
	ip        net.IP         // local address of c
	sport     int            // source port of c
	c         net.PacketConn // either net.UDPConn or icmp.PacketConn
	c4        *ipv4.PacketConn
	c6        *ipv6.PacketConn
}

func (c *conn) close() error {
	return c.c.Close()
}

func (c *conn) readFrom(b []byte) (int, interface{}, net.Addr, error) {
	if !c.rawSocket {
		n, peer, err := c.c.ReadFrom(b)
		return n, nil, peer, err
	}
	if c.protocol == ianaProtocolICMP {
		return c.c4.ReadFrom(b)
	}
	if c.protocol == ianaProtocolIPv6ICMP {
		return c.c6.ReadFrom(b)
	}
	return 0, nil, nil, fmt.Errorf("unknown protocol: %d", c.protocol)
}

func (c *conn) writeTo(b []byte, dst net.Addr, ifi *net.Interface) (int, error) {
	if !c.rawSocket {
		return c.c.WriteTo(b, dst)
	}
	if c.protocol == ianaProtocolICMP {
		var cm *ipv4.ControlMessage
		if ifi != nil {
			cm = &ipv4.ControlMessage{IfIndex: ifi.Index}
		}
		return c.c4.WriteTo(b, cm, dst)
	}
	if c.protocol == ianaProtocolIPv6ICMP {
		var cm *ipv6.ControlMessage
		if ifi != nil {
			cm = &ipv6.ControlMessage{IfIndex: ifi.Index}
		}
		return c.c6.WriteTo(b, cm, dst)
	}
	return 0, fmt.Errorf("unknown protocol: %d", c.protocol)
}

func newConn(network, address string) (*conn, error) {
	switch network {
	case "ip4:icmp", "ip4:1", "ip6:ipv6-icmp", "ip6:58", "ip4:icmp+ip6:ipv6-icmp":
		return newICMPConn(network, address)
	case "udp", "udp4", "udp6":
		return newUDPConn(network, address)
	default:
		return nil, net.UnknownNetworkError(network)
	}
}

func newICMPConn(network, address string) (*conn, error) {
	ipa, err := net.ResolveIPAddr("ip", address)
	if err != nil {
		return nil, err
	}
	if ipa.IP == nil {
		switch network {
		case "ip4:icmp", "ip4:1", "ip4:icmp+ip6:ipv6-icmp":
			ipa.IP = net.IPv4zero
		case "ip6:ipv6-icmp", "ip6:58":
			ipa.IP = net.IPv6unspecified
		}
	}

	var conn conn
	var networks []string
	if ipa.IP.To4() != nil {
		networks = []string{"ip4:icmp", "udp4"}
		conn.protocol = ianaProtocolICMP
	}
	if ipa.IP.To16() != nil && ipa.IP.To4() == nil {
		networks = []string{"ip6:ipv6-icmp", "udp6"}
		conn.protocol = ianaProtocolIPv6ICMP
	}

	var firstErr error
	for _, network := range networks {
		c, err := icmp.ListenPacket(network, address)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		conn.c = c
		break
	}
	if conn.c == nil {
		return nil, firstErr
	}

	switch la := conn.c.LocalAddr().(type) {
	case *net.UDPAddr:
		conn.ip = la.IP
	case *net.IPAddr:
		conn.rawSocket = true
		conn.ip = la.IP
	}
	conn.c4 = conn.c.(*icmp.PacketConn).IPv4PacketConn()
	conn.c6 = conn.c.(*icmp.PacketConn).IPv6PacketConn()
	return &conn, nil
}

func newUDPConn(network, address string) (*conn, error) {
	c, err := net.ListenPacket(network, address)
	if err != nil {
		return nil, err
	}
	conn := conn{c: c}

	switch la := conn.c.LocalAddr().(type) {
	case *net.UDPAddr:
		if la.IP.To4() != nil {
			conn.c4 = ipv4.NewPacketConn(conn.c)
		}
		if la.IP.To16() != nil && la.IP.To4() == nil {
			conn.c6 = ipv6.NewPacketConn(conn.c)
		}
		conn.protocol = ianaProtocolUDP
		conn.ip = la.IP
		conn.sport = la.Port
	}
	return &conn, nil
}
