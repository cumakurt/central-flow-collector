package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	proto := flag.String("protocol", "netflow5", "netflow5|netflow9|ipfix|sflow")
	target := flag.String("target", "127.0.0.1:2055", "collector UDP address")
	rate := flag.Int("rate", 100, "packets per second")
	count := flag.Int("count", 1000, "packets to send; 0=forever")
	src := flag.String("src-prefix", "10.10.0.", "synthetic source IPv4 prefix")
	dst := flag.String("dst-prefix", "172.16.0.", "synthetic destination IPv4 prefix")
	flag.Parse()
	if *rate < 1 {
		*rate = 1
	}
	a, e := net.ResolveUDPAddr("udp", *target)
	fatal(e)
	c, e := net.DialUDP("udp", nil, a)
	fatal(e)
	defer c.Close()
	tick := time.NewTicker(time.Second / time.Duration(*rate))
	defer tick.Stop()
	seq := uint32(1)
	sent := 0
	for *count == 0 || sent < *count {
		<-tick.C
		si := byte(1 + rand.Intn(250))
		di := byte(1 + rand.Intn(250))
		s := net.ParseIP(fmt.Sprintf("%s%d", *src, si)).To4()
		d := net.ParseIP(fmt.Sprintf("%s%d", *dst, di)).To4()
		if s == nil || d == nil {
			fmt.Fprintln(os.Stderr, "prefix must produce IPv4 addresses")
			os.Exit(2)
		}
		var b []byte
		switch strings.ToLower(*proto) {
		case "netflow5":
			b = nf5(s, d, seq)
		case "netflow9":
			if seq%20 == 1 {
				_, _ = c.Write(nf9Template(seq))
			}
			b = nf9Data(s, d, seq)
		case "ipfix":
			if seq%20 == 1 {
				_, _ = c.Write(ipfixTemplate(seq))
			}
			b = ipfixData(s, d, seq)
		case "sflow":
			b = sflow(s, d, seq)
		default:
			fmt.Fprintln(os.Stderr, "unknown protocol")
			os.Exit(2)
		}
		if _, e = c.Write(b); e != nil {
			fatal(e)
		}
		seq++
		sent++
	}
	fmt.Printf("sent %d %s packets to %s\n", sent, *proto, *target)
}
func nf5(s, d net.IP, seq uint32) []byte {
	b := make([]byte, 72)
	binary.BigEndian.PutUint16(b[0:2], 5)
	binary.BigEndian.PutUint16(b[2:4], 1)
	binary.BigEndian.PutUint32(b[4:8], 600000)
	binary.BigEndian.PutUint32(b[8:12], uint32(time.Now().Unix()))
	binary.BigEndian.PutUint32(b[16:20], seq)
	copy(b[24:28], s)
	copy(b[28:32], d)
	binary.BigEndian.PutUint32(b[40:44], 10)
	binary.BigEndian.PutUint32(b[44:48], uint32(2000+rand.Intn(100000)))
	binary.BigEndian.PutUint32(b[48:52], 590000)
	binary.BigEndian.PutUint32(b[52:56], 599000)
	binary.BigEndian.PutUint16(b[56:58], uint16(1024+rand.Intn(50000)))
	binary.BigEndian.PutUint16(b[58:60], []uint16{53, 80, 443, 22, 3389}[rand.Intn(5)])
	b[61] = 0x12
	b[62] = 6
	return b
}
func nf9Header(seq uint32, n int) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[:2], 9)
	binary.BigEndian.PutUint16(b[2:4], uint16(n))
	binary.BigEndian.PutUint32(b[4:8], 600000)
	binary.BigEndian.PutUint32(b[8:12], uint32(time.Now().Unix()))
	binary.BigEndian.PutUint32(b[12:16], seq)
	binary.BigEndian.PutUint32(b[16:20], 1)
	return b
}
func nf9Template(seq uint32) []byte {
	h := nf9Header(seq, 1)
	set := make([]byte, 4+4+7*4)
	binary.BigEndian.PutUint16(set[0:2], 0)
	binary.BigEndian.PutUint16(set[2:4], uint16(len(set)))
	binary.BigEndian.PutUint16(set[4:6], 256)
	binary.BigEndian.PutUint16(set[6:8], 7)
	fs := [][2]uint16{{8, 4}, {12, 4}, {7, 2}, {11, 2}, {1, 4}, {4, 1}, {2, 4}}
	p := 8
	for _, x := range fs {
		binary.BigEndian.PutUint16(set[p:p+2], x[0])
		binary.BigEndian.PutUint16(set[p+2:p+4], x[1])
		p += 4
	}
	return append(h, set...)
}
func nf9Data(s, d net.IP, seq uint32) []byte {
	h := nf9Header(seq, 1)
	// 21 bytes of record data plus 3 bytes of FlowSet padding.
	set := make([]byte, 4+24)
	binary.BigEndian.PutUint16(set[:2], 256)
	binary.BigEndian.PutUint16(set[2:4], uint16(len(set)))
	copy(set[4:8], s)
	copy(set[8:12], d)
	binary.BigEndian.PutUint16(set[12:14], 12345)
	binary.BigEndian.PutUint16(set[14:16], 443)
	binary.BigEndian.PutUint32(set[16:20], uint32(5000+rand.Intn(50000)))
	set[20] = 6 // protocolIdentifier: TCP
	binary.BigEndian.PutUint32(set[21:25], uint32(1+rand.Intn(50)))
	return append(h, set...)
}
func ipfixTemplate(seq uint32) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint16(b[:2], 10)
	binary.BigEndian.PutUint32(b[4:8], uint32(time.Now().Unix()))
	binary.BigEndian.PutUint32(b[8:12], seq)
	binary.BigEndian.PutUint32(b[12:16], 1)
	set := make([]byte, 4+4+7*4)
	binary.BigEndian.PutUint16(set[:2], 2)
	binary.BigEndian.PutUint16(set[2:4], uint16(len(set)))
	binary.BigEndian.PutUint16(set[4:6], 256)
	binary.BigEndian.PutUint16(set[6:8], 7)
	fs := [][2]uint16{{8, 4}, {12, 4}, {7, 2}, {11, 2}, {1, 4}, {4, 1}, {2, 4}}
	p := 8
	for _, x := range fs {
		binary.BigEndian.PutUint16(set[p:p+2], x[0])
		binary.BigEndian.PutUint16(set[p+2:p+4], x[1])
		p += 4
	}
	b = append(b, set...)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	return b
}
func ipfixData(s, d net.IP, seq uint32) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint16(b[:2], 10)
	binary.BigEndian.PutUint32(b[4:8], uint32(time.Now().Unix()))
	binary.BigEndian.PutUint32(b[8:12], seq)
	binary.BigEndian.PutUint32(b[12:16], 1)
	// 21 bytes of record data plus 3 bytes of Set padding.
	set := make([]byte, 4+24)
	binary.BigEndian.PutUint16(set[:2], 256)
	binary.BigEndian.PutUint16(set[2:4], uint16(len(set)))
	copy(set[4:8], s)
	copy(set[8:12], d)
	binary.BigEndian.PutUint16(set[12:14], 23456)
	binary.BigEndian.PutUint16(set[14:16], 53)
	binary.BigEndian.PutUint32(set[16:20], 8000)
	set[20] = 17 // protocolIdentifier: UDP
	binary.BigEndian.PutUint32(set[21:25], 8)
	b = append(b, set...)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	return b
}
func sflow(s, d net.IP, seq uint32) []byte {
	b := make([]byte, 0, 128)
	add := func(v uint32) { var x [4]byte; binary.BigEndian.PutUint32(x[:], v); b = append(b, x[:]...) }
	add(5)
	add(1)
	b = append(b, 127, 0, 0, 1)
	add(0)
	add(seq)
	add(600000)
	add(1)
	add(1)
	sampleStart := len(b)
	add(0)
	sampleData := len(b)
	add(seq)
	add(0)
	add(100)
	add(seq * 100)
	add(0)
	add(0)
	add(0)
	add(1)
	add(3)
	add(32)
	add(1500)
	add(6)
	b = append(b, s...)
	b = append(b, d...)
	add(12345)
	add(443)
	add(0x12)
	add(0)
	binary.BigEndian.PutUint32(b[sampleStart:sampleStart+4], uint32(len(b)-sampleData))
	return b
}
func fatal(e error) {
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
