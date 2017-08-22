// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipoam_test

import (
	"net"
	"os"
	"testing"

	"github.com/mikioh/ipoam"
)

func BenchmarkTester(b *testing.B) {
	for _, bb := range []struct {
		name                     string
		network, address, target string
	}{
		{"IPv4", "ip4:icmp", "0.0.0.0", "ipv4.google.com"},
		{"IPv6", "ip6:ipv6-icmp", "::", "ipv6.google.com"},
	} {
		b.Run(bb.name, func(b *testing.B) {
			ipt, err := ipoam.NewTester(bb.network, bb.address)
			if err != nil {
				b.Log(err)
				return
			}
			defer ipt.Close()
			ips, err := net.LookupIP(bb.target)
			if err != nil {
				b.Log(err)
				return
			}
			b.ResetTimer()
			cm := ipoam.ControlMessage{ID: os.Getpid() & 0xffff}
			for i := 0; i < b.N; i++ {
				cm.Seq = i + 1
				if err := ipt.Probe([]byte("HELLO-R-U-THERE"), &cm, ips[0], nil); err != nil {
					b.Fatal(err)
				}
				<-ipt.Report()
			}
		})
	}
}
