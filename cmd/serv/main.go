package main

import (
	"log"
	"net"
	"os"
	"path"
	"strings"
	"try/dns"
)

var nsRecords []dns.ResourceRecord

var rrs map[dns.Question][]dns.ResourceRecord

func loadZonefiles(path string) error {
	rrs = make(map[dns.Question][]dns.ResourceRecord)

	zone, err := dns.ReadZonefile(path)
	if err != nil {
		return err
	}
	for _, v := range zone.Records {
		key := dns.Question{v.Name, v.Type, v.Class}
		if _, ok := rrs[key]; !ok {
			rrs[key] = make([]dns.ResourceRecord, 0)
		}
		rrs[key] = append(rrs[key], v)
	}
	nsRecords, _ = rrs[dns.Question{dns.Name(zone.Origin), dns.TypeNS, dns.ClassIN}]
	return nil
}

func handleConnection(conn net.PacketConn, addr net.Addr, req []byte) {
	var bytes []byte

	request, err := dns.ParseRequest(req)
	if err != nil {
		log.Print("[error] ", err)
		goto Error
	}

	if rrs, ok := rrs[request.Question]; ok {
		res, err := dns.MakeResponse(*request, rrs, nsRecords)
		if err != nil {
			log.Print("[error] ", err)
			goto Error
		}
		bytes, err = res.Bytes()
		if err != nil {
			log.Print("[error] ", err)
			goto Error
		}
	} else {
		goto Error
	}

End:
	conn.WriteTo(bytes, addr)
	log.Printf("%v %v", addr.String(), len(bytes))

	return

Error:
	bytes = dns.MakeErrResMsg(request)
	goto End
}

func main() {
	log.SetPrefix(path.Base(os.Args[0]) + " ")
	log.Print("os.Args: ", strings.Join(os.Args, " "))

	loadZonefiles(os.Args[1])

	conn, err := net.ListenPacket("udp", os.Args[2])
	if err != nil {
		log.Fatal(err)
	}

	for {
		buf := make([]byte, 1500)
		n, addr, err := conn.ReadFrom(buf[:])
		if err != nil {
			log.Print("[error] ", err)
			continue
		}
		go handleConnection(conn, addr, buf[:n])
	}
}
