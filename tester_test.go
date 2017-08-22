// Copyright 2014 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipoam_test

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/mikioh/ipoam"
)

func TestTesterGlobalUnicast(t *testing.T) {
	if testing.Short() {
		t.Skip("to avoid external network")
	}

	for i, tt := range []struct {
		name                     string
		network, address, target string
		ip                       net.IP
	}{
		{"GlobalUnicast", "ip4:icmp", "0.0.0.0", "golang.org", nil},
		{"GlobalUnicast", "udp", "0.0.0.0:0", "golang.org", nil},

		{"GlobalUnicast", "ip6:ipv6-icmp", "::", "golang.org", nil},
		{"GlobalUnicast", "udp", "[::]:0", "golang.org", nil},

		{"GlobalUnicast", "ip4:icmp", "0.0.0.0", "www.google.com", nil},
		{"GlobalUnicast", "udp", "0.0.0.0:0", "www.google.com", nil},

		{"GlobalUnicast", "ip6:ipv6-icmp", "::", "www.google.com", nil},
		{"GlobalUnicast", "udp", "[::]:0", "www.google.com", nil},

		{"LinkLocalMulticast", "ip4:icmp", "0.0.0.0", "", net.IPv4(224, 0, 0, 251)},

		{"LinkLocalMulticast", "ip6:ipv6-icmp", "::", "", net.ParseIP("ff02::1")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cm := ipoam.ControlMessage{ID: os.Getpid()&0xffff + i, Port: 33434}
			ipt, err := ipoam.NewTester(tt.network, tt.address)
			if err != nil {
				t.Log(err)
				return
			}
			defer ipt.Close()

			var ips []net.IP
			var mift []net.Interface
			if tt.target != "" {
				ips, err = net.LookupIP(tt.target)
				if err != nil {
					t.Error(err)
					return
				}
				nips := ips[:0]
				for _, ip := range ips {
					if ip.To4() != nil && ipt.IPv4PacketConn() != nil || ip.To16() != nil && ip.To4() == nil && ipt.IPv6PacketConn() != nil {
						nips = append(nips, ip)
					}
				}
				ips = nips
			} else {
				ift, err := net.Interfaces()
				if err != nil {
					t.Error(err)
					return
				}
				mift = ift[:0]
				for _, ifi := range ift {
					if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0 {
						continue
					}
					mift = append(mift, ifi)
				}
			}

			cm.Seq = i + 1
			if tt.target != "" {
				for _, ip := range ips {
					if err := ipt.Probe([]byte("HELLO-R-U-THERE"), &cm, ip, nil); err != nil {
						t.Log(err)
					}
				}
			} else {
				for j := range mift {
					if err := ipt.Probe([]byte("HELLO-R-U-THERE"), &cm, tt.ip, &mift[j]); err != nil {
						t.Log(err)
					}
				}
			}

			wait := time.NewTimer(250 * time.Millisecond)
			var rs []ipoam.Report
		loop:
			for {
				select {
				case <-wait.C:
					break loop
				case r := <-ipt.Report():
					rs = append(rs, r)
				}
			}
			wait.Stop()

			tgt := tt.target
			if tgt == "" {
				tgt = tt.ip.String()
			}
			if len(rs) == 0 {
				t.Logf("got no records for %s on %s, %s", tgt, tt.network, tt.address)
			}
			for _, r := range rs {
				if r.Error != nil {
					t.Logf("%s: %v", tgt, r.Error)
				}
				if r.ICMP != nil {
					t.Logf("%s: %+v", tgt, r.ICMP)
				}
			}
		})
	}
}
