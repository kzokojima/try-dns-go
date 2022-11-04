package main

import (
	"flag"
	"fmt"
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

type ServFunc func(dns.Request) ([]byte, error)

func authoritativeServer(req dns.Request) ([]byte, error) {
	var bytes []byte

	if answers, ok := zoneResourceRecords[req.Question]; ok {
		additionals := getAdditionals(answers)
		res, err := dns.MakeResponse(req.Header, req.Question, answers, zoneAuthorities, additionals)
		if err != nil {
			return nil, err
		}
		bytes, err = res.Bytes()
		if err != nil {
			return nil, err
		}
	} else {
		// CNAME
		answers := findResourceRecords(string(req.Question.Name), dns.TypeCNAME, dns.ClassIN)
		if len(answers) == 1 {
			cname := answers[0]
			additionals := findResourceRecords(string(cname.RData.(dns.CNAME)), req.Question.Type, dns.ClassIN)
			answers = append(answers, additionals...)
			res, err := dns.MakeResponse(req.Header, req.Question, answers, zoneAuthorities, nil)
			if err != nil {
				return nil, err
			}
			bytes, err = res.Bytes()
			if err != nil {
				return nil, err
			}
		} else {
			return nil, fmt.Errorf("invalid CNAME response")
		}
	}
	return bytes, nil
}

var cache = dns.NewCache()

func resolver(req dns.Request) ([]byte, error) {
	if req.Question.Name == "." && req.Question.Type == dns.TypeNS {
		// root
		answers := dns.RootServerNSRRs
		additionals := dns.RootServers
		res, err := dns.MakeResponse(req.Header, req.Question, answers, zoneAuthorities, additionals)
		if err != nil {
			return nil, err
		}
		bytes, err := res.Bytes()
		if err != nil {
			return nil, err
		}
		return bytes, nil
	}

	rrs, err := dns.Resolve(req.Question, nil, cache)
	if err != nil {
		return nil, fmt.Errorf("ERR1")
	}
	answers := rrs
	res, err := dns.MakeResponse(req.Header, req.Question, answers, nil, nil)
	if err != nil {
		return nil, err
	}
	bytes, err := res.Bytes()
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func handleConnection(conn net.PacketConn, addr net.Addr, req []byte, fn ServFunc) {
	var bytes []byte

	request, err := dns.ParseRequest(req)
	if err != nil {
		dns.Log.Error(err)
		goto Error
	}

	bytes, err = fn(*request)
	if err != nil {
		dns.Log.Error(err)
		goto Error
	}

End:
	conn.WriteTo(bytes, addr)
	dns.Log.Infof("%v %v", addr.String(), len(bytes))

	return

Error:
	bytes = dns.MakeErrResMsg(request)
	goto End
}

func main() {
	log.SetPrefix(path.Base(os.Args[0]) + " ")
	dns.Log.Info("os.Args: ", strings.Join(os.Args, " "))

	var mode string
	var address string
	var zone string

	flag.StringVar(&address, "address", "", "")
	flag.StringVar(&mode, "mode", "", "")
	flag.StringVar(&zone, "zone", "", "")
	flag.Parse()

	conn, err := net.ListenPacket("udp", address)
	if err != nil {
		dns.Log.Error(err)
		os.Exit(1)
	}

	fn := resolver
	if mode == "authoritative" {
		loadZonefiles(zone)
		fn = authoritativeServer
	} else {
		dns.LoadRootZone(zone)
	}

	for {
		buf := make([]byte, 1500)
		n, addr, err := conn.ReadFrom(buf[:])
		if err != nil {
			dns.Log.Error(err)
			continue
		}
		go handleConnection(conn, addr, buf[:n], fn)
	}
}
