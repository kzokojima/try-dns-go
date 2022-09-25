package main

import (
	"log"
	"net"
	"os"
	"path"
	"strings"
	"try/dns"
)

type RRVal interface{}

var rrs = map[dns.Question]RRVal{
	dns.Question{"a.example.", dns.TypeA, dns.ClassIN}: []string{"192.0.2.1"},
}

func handleConnection(conn net.PacketConn, addr net.Addr, req []byte) {
	request, err := dns.ParseRequest(req)
	if err != nil {
		log.Print(err)
		return
	}
	rrval, ok := rrs[request.Question]
	if ok {
		addrs := rrval.([]string)
		res, err := dns.MakeResponse(*request, addrs)
		if err != nil {
			log.Print(err)
			return
		}
		bytes, err := res.Bytes()
		if err != nil {
			log.Print(err)
			return
		}
		conn.WriteTo(bytes, addr)
	} else {
		bytes := dns.MakeErrResMsg(request)
		conn.WriteTo(bytes, addr)
	}
}

func main() {
	log.SetPrefix(path.Base(os.Args[0]) + " ")
	log.Print("os.Args: ", strings.Join(os.Args, " "))

	conn, err := net.ListenPacket("udp", os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	for {
		buf := make([]byte, 1500)
		n, addr, err := conn.ReadFrom(buf[:])
		if err != nil {
			log.Print(err)
			continue
		}
		log.Print("request from ", addr.String())
		go handleConnection(conn, addr, buf[:n])
	}
}
