package main

import (
	"log"
	"net"
	"os"
	"path"
	"strings"
	"try/dns"
)

var zoneAuthorities []dns.ResourceRecord

var zoneResourceRecords map[dns.Question][]dns.ResourceRecord

func loadZonefiles(path string) error {
	zoneResourceRecords = make(map[dns.Question][]dns.ResourceRecord)

	zone, err := dns.ReadZonefile(path)
	if err != nil {
		return err
	}
	for _, v := range zone.Records {
		key := dns.Question{Name: v.Name, Type: v.Type, Class: v.Class}
		if _, ok := zoneResourceRecords[key]; !ok {
			zoneResourceRecords[key] = make([]dns.ResourceRecord, 0)
		}
		zoneResourceRecords[key] = append(zoneResourceRecords[key], v)
	}
	zoneAuthorities = findResourceRecords(zone.Origin, dns.TypeNS, dns.ClassIN)
	return nil
}

func findResourceRecords(name string, type_ dns.Type, class dns.Class) []dns.ResourceRecord {
	key := dns.Question{Name: dns.Name(name), Type: type_, Class: class}
	if result, ok := zoneResourceRecords[key]; ok {
		return result
	} else {
		return nil
	}
}

func getAdditionals(answers []dns.ResourceRecord) []dns.ResourceRecord {
	var results []dns.ResourceRecord
	for _, answer := range answers {
		if answer.Type == dns.TypeMX {
			additionals := findResourceRecords(answer.RData.(dns.MX).Exchange, dns.TypeA, dns.ClassIN)
			results = append(results, additionals...)
		}
	}
	for _, answer := range answers {
		if answer.Type == dns.TypeMX {
			additionals := findResourceRecords(answer.RData.(dns.MX).Exchange, dns.TypeAAAA, dns.ClassIN)
			results = append(results, additionals...)
		}
	}
	return results
}

func handleConnection(conn net.PacketConn, addr net.Addr, req []byte) {
	var bytes []byte

	request, err := dns.ParseRequest(req)
	if err != nil {
		log.Print("[error] ", err)
		goto Error
	}

	if answers, ok := zoneResourceRecords[request.Question]; ok {
		additionals := getAdditionals(answers)
		res, err := dns.MakeResponse(request.Header, request.Question, answers, zoneAuthorities, additionals)
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
		// CNAME
		answers := findResourceRecords(string(request.Question.Name), dns.TypeCNAME, dns.ClassIN)
		if len(answers) == 1 {
			cname := answers[0]
			additionals := findResourceRecords(string(cname.RData.(dns.CNAME)), request.Question.Type, dns.ClassIN)
			answers = append(answers, additionals...)
			res, err := dns.MakeResponse(request.Header, request.Question, answers, zoneAuthorities, nil)
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
