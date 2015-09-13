// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipoam

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// A Report represents a test report for IP-layer OAM.
type Report struct {
	Error error         // on-link operation error
	Time  time.Time     // time packet received
	Src   net.IP        // source address on received packet
	ICMP  *icmp.Message // received ICMP message

	// Original datagram fields when ICMP is a error message.
	OrigHeader  interface{} // IP header, either ipv4.Header or ipv6.Header
	OrigPayload []byte      // IP payload

	// These fields may not be set when the tester is configured
	// to use non-privileged datagram-oriented ICMP endpoint.
	TC        int            // IPv4 TOS or IPv6 traffic-class on received packet
	Hops      int            // IPv4 TTL or IPv6 hop-limit on receievd packet
	Dst       net.IP         // destinaion address on received packet
	Interface *net.Interface // inbound interface on received packet
}

func parseICMPError(m *icmp.Message) (interface{}, []byte, error) {
	var b []byte
	switch body := m.Body.(type) {
	case *icmp.DstUnreach:
		b = body.Data
	case *icmp.PacketTooBig:
		b = body.Data
	case *icmp.TimeExceeded:
		b = body.Data
	case *icmp.ParamProb:
		b = body.Data
	}

	var iph interface{}
	switch m.Type.Protocol() {
	case ianaProtocolICMP:
		h, err := icmp.ParseIPv4Header(b) // cannot use ipv4.ParseHeader for this purpose
		if err != nil {
			return nil, nil, err
		}
		if len(b) < ipv4.HeaderLen+len(h.Options)+8 {
			return nil, nil, fmt.Errorf("ICMP error message too short: %v, %d", m.Type, m.Code)
		}
		b = b[ipv4.HeaderLen+len(h.Options):]
		iph = h
	case ianaProtocolIPv6ICMP:
		h, err := ipv6.ParseHeader(b)
		if err != nil {
			return nil, nil, err
		}
		if len(b) < ipv6.HeaderLen+8 {
			return nil, nil, fmt.Errorf("ICMP error message too short: %v, %d", m.Type, m.Code)
		}
		b = b[ipv6.HeaderLen:]
		iph = h
	}
	return iph, b, nil
}

func parseOrigIP(iph interface{}) int {
	switch h := iph.(type) {
	case *ipv4.Header:
		return h.Protocol
	case *ipv6.Header:
		return h.NextHeader
	}
	return -1
}

func parseOrigUDP(b []byte) (sport, dport int) {
	if len(b) < 8 {
		return -1, -1
	}
	return int(b[0])<<8 | int(b[1]), int(b[2])<<8 | int(b[3])
}
