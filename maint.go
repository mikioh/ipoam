// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipoam

import (
	"net"
	"runtime"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type cookie uint64

func (c cookie) icmpID() int   { return int(c >> 48) }
func (c cookie) icmpSeq() int  { return int(c << 16 >> 48) }
func (c cookie) udpSport() int { return int(c >> 48) }
func (c cookie) udpDport() int { return int(c << 16 >> 48) }
func (c cookie) protocol() int { return int(c & 0xff) }

func icmpCookie(protocol, id, seq int) cookie {
	return cookie(id)&0xffff<<48 | cookie(seq)&0xffff<<32 | cookie(protocol)&0xff
}

func udpCookie(protocol, sport, dport int) cookie {
	return cookie(sport)&0xffff<<48 | cookie(dport)&0xffff<<32 | cookie(protocol)&0xff
}

// A maint represents a maintenance endpoint.
type maint struct {
	cookie     uint64
	emitReport int32
	report     chan Report // buffered report channel
}

func (t *maint) setICMPCookie(protocol, id, seq int) {
	atomic.StoreUint64(&t.cookie, uint64(icmpCookie(protocol, id, seq)))
}

func (t *maint) setUDPCookie(protocol, sport, dport int) {
	atomic.StoreUint64(&t.cookie, uint64(udpCookie(protocol, sport, dport)))
}

func (t *maint) monitor(c *conn) {
	var r Report
	b := make([]byte, 1<<16-1)

	for {
		rb, h, cm, peer, err := c.readFrom(b)
		if err != nil {
			r.Error = err
			t.writeReport(&r)
			if err, ok := err.(net.Error); ok && (err.Timeout() || err.Temporary()) {
				continue
			}
			return
		}

		r.Time = time.Now()

		if !c.rawSocket {
			r.Src = peer.(*net.UDPAddr).IP
		} else {
			r.Src = peer.(*net.IPAddr).IP
		}
		switch h := h.(type) {
		case *ipv4.Header:
			r.TC = h.TOS
			if runtime.GOOS == "solaris" {
				r.Hops = h.TTL
			}
		}
		switch cm := cm.(type) {
		case *ipv4.ControlMessage:
			if runtime.GOOS != "solaris" {
				r.Hops = cm.TTL
			}
			r.Dst = cm.Dst
			ifi, _ := net.InterfaceByIndex(cm.IfIndex)
			r.Interface = ifi
		case *ipv6.ControlMessage:
			r.TC = cm.TrafficClass
			r.Hops = cm.HopLimit
			r.Dst = cm.Dst
			ifi, _ := net.InterfaceByIndex(cm.IfIndex)
			r.Interface = ifi
		}

		m, err := icmp.ParseMessage(c.protocol, rb)
		if err != nil {
			r.Error = err
			t.writeReport(&r)
			continue
		}

		r.ICMP = m
		mcookie := cookie(atomic.LoadUint64(&t.cookie))

		if r.ICMP.Type == ipv4.ICMPTypeEchoReply || r.ICMP.Type == ipv6.ICMPTypeEchoReply {
			cookie := icmpCookie(c.protocol, m.Body.(*icmp.Echo).ID, m.Body.(*icmp.Echo).Seq)
			if cookie == mcookie || runtime.GOOS == "linux" && !c.rawSocket {
				t.writeReport(&r)
			}
			continue
		}

		r.OrigHeader, r.OrigPayload, err = parseICMPError(m)
		if err != nil {
			r.Error = err
			t.writeReport(&r)
			continue
		}

		switch parseOrigIP(r.OrigHeader) {
		case ianaProtocolICMP, ianaProtocolIPv6ICMP:
			m, err := icmp.ParseMessage(r.ICMP.Type.Protocol(), r.OrigPayload)
			if err != nil {
				r.Error = err
				t.writeReport(&r)
				continue
			}
			var cookie cookie
			if echo, ok := m.Body.(*icmp.Echo); ok {
				cookie = icmpCookie(c.protocol, echo.ID, echo.Seq)
			}
			if cookie == mcookie || runtime.GOOS == "linux" && !c.rawSocket {
				t.writeReport(&r)
			}
		case ianaProtocolUDP:
			sport, dport := parseOrigUDP(r.OrigPayload)
			cookie := udpCookie(ianaProtocolUDP, sport, dport)
			if cookie == mcookie {
				t.writeReport(&r)
			}
		default: // e.g., ianaProtocolIPv6Frag
			t.writeReport(&r)
		}
	}
}

func (t *maint) writeReport(r *Report) {
	emit := atomic.LoadInt32(&t.emitReport)
	if emit > 0 {
		t.report <- *r
	}
}

// Report returns the buffered test report channel.
func (t *maint) Report() <-chan Report {
	return t.report
}

// StartReport enables emitting test reports.
func (t *maint) StartReport() {
	atomic.StoreInt32(&t.emitReport, 1)
}

// StopReport disables emitting test reports.
func (t *maint) StopReport() {
	atomic.StoreInt32(&t.emitReport, 0)
}
