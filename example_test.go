// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipoam_test

import (
	"log"
	"net"
	"os"
	"time"

	"github.com/mikioh/ipoam"
)

func ExampleTester_unicastConnectivityVerification() {
	ipt, err := ipoam.NewTester("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Fatal(err)
	}
	defer ipt.Close()
	cm := ipoam.ControlMessage{ID: os.Getpid() & 0xffff}
	for i, dst := range []string{"8.8.8.8", "8.8.4.4"} {
		cm.Seq = i + 1
		if err := ipt.Probe([]byte("HELLO-R-U-THERE"), &cm, net.ParseIP(dst), nil); err != nil {
			log.Println(err)
			continue
		}
		t := time.NewTimer(500 * time.Millisecond)
		select {
		case <-t.C:
			log.Println("timedout")
		case r := <-ipt.Report():
			if r.Error != nil {
				log.Println(r.Error)
			} else {
				log.Println(r.ICMP)
			}
		}
		t.Stop()
	}
}

func ExampleTester_linkLocalMulticastConnectivityVerification() {
	ipt, err := ipoam.NewTester("ip6:ipv6-icmp", "::")
	if err != nil {
		log.Fatal(err)
	}
	defer ipt.Close()
	var mifi *net.Interface
	for _, name := range []string{"lo0", "lo"} {
		ifi, err := net.InterfaceByName(name)
		if err != nil {
			continue
		}
		mifi = ifi
		break
	}
	cm := ipoam.ControlMessage{ID: os.Getpid() & 0xffff}
	for i := 0; i < 3; i++ {
		cm.Seq = i + 1
		if err := ipt.Probe([]byte("HELLO-R-U-THERE"), &cm, net.ParseIP("ff02::1"), mifi); err != nil {
			log.Println(err)
			continue
		}
		t := time.NewTimer(500 * time.Millisecond)
		select {
		case <-t.C:
			log.Println("timedout")
		case r := <-ipt.Report():
			if r.Error != nil {
				log.Println(r.Error)
			} else {
				log.Println(r.ICMP)
			}
		}
		t.Stop()
	}
}

func ExampleTester_unicastPathDiscovery() {
	ipt, err := ipoam.NewTester("udp4", "0.0.0.0:0")
	if err != nil {
		log.Fatal(err)
	}
	defer ipt.Close()
	cm := ipoam.ControlMessage{Port: 33434}
	for i := 1; i <= 3; i++ {
		ipt.IPv4PacketConn().SetTTL(i)
		if err := ipt.Probe([]byte("HELLO-R-U-THERE"), &cm, net.ParseIP("8.8.8.8"), nil); err != nil {
			log.Println(err)
			continue
		}
		t := time.NewTimer(500 * time.Millisecond)
		select {
		case <-t.C:
			log.Println("timedout")
		case r := <-ipt.Report():
			if r.Error != nil {
				log.Println(r.Error)
			} else {
				log.Println(r.ICMP)
			}
		}
		t.Stop()
	}
}
