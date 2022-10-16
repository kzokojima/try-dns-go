package main

import (
	"fmt"
	"log"
	"net"
	"net/netip"
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

var rootServerNSRRs = []dns.ResourceRecord{
	{Name: ".", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 3600000, RData: dns.NS("a.root-servers.net.")},
	{Name: ".", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 3600000, RData: dns.NS("b.root-servers.net.")},
	{Name: ".", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 3600000, RData: dns.NS("c.root-servers.net.")},
	{Name: ".", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 3600000, RData: dns.NS("d.root-servers.net.")},
	{Name: ".", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 3600000, RData: dns.NS("e.root-servers.net.")},
	{Name: ".", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 3600000, RData: dns.NS("f.root-servers.net.")},
	{Name: ".", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 3600000, RData: dns.NS("g.root-servers.net.")},
	{Name: ".", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 3600000, RData: dns.NS("h.root-servers.net.")},
	{Name: ".", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 3600000, RData: dns.NS("i.root-servers.net.")},
	{Name: ".", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 3600000, RData: dns.NS("j.root-servers.net.")},
	{Name: ".", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 3600000, RData: dns.NS("k.root-servers.net.")},
	{Name: ".", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 3600000, RData: dns.NS("l.root-servers.net.")},
	{Name: ".", Type: dns.TypeNS, Class: dns.ClassIN, TTL: 3600000, RData: dns.NS("m.root-servers.net.")},
}

var rootServers = []dns.ResourceRecord{
	{Name: "a.root-servers.net.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 3600000, RData: netip.MustParseAddr("198.41.0.4")},
	{Name: "a.root-servers.net.", Type: dns.TypeAAAA, Class: dns.ClassIN, TTL: 3600000, RData: dns.AAAA(netip.MustParseAddr("2001:503:ba3e::2:30"))},
	{Name: "b.root-servers.net.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 3600000, RData: netip.MustParseAddr("199.9.14.201")},
	{Name: "b.root-servers.net.", Type: dns.TypeAAAA, Class: dns.ClassIN, TTL: 3600000, RData: dns.AAAA(netip.MustParseAddr("2001:500:200::b"))},
	{Name: "c.root-servers.net.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 3600000, RData: netip.MustParseAddr("192.33.4.12")},
	{Name: "c.root-servers.net.", Type: dns.TypeAAAA, Class: dns.ClassIN, TTL: 3600000, RData: dns.AAAA(netip.MustParseAddr("2001:500:2::c"))},
	{Name: "d.root-servers.net.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 3600000, RData: netip.MustParseAddr("199.7.91.13")},
	{Name: "d.root-servers.net.", Type: dns.TypeAAAA, Class: dns.ClassIN, TTL: 3600000, RData: dns.AAAA(netip.MustParseAddr("2001:500:2d::d"))},
	{Name: "e.root-servers.net.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 3600000, RData: netip.MustParseAddr("192.203.230.10")},
	{Name: "e.root-servers.net.", Type: dns.TypeAAAA, Class: dns.ClassIN, TTL: 3600000, RData: dns.AAAA(netip.MustParseAddr("2001:500:a8::e"))},
	{Name: "f.root-servers.net.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 3600000, RData: netip.MustParseAddr("192.5.5.241")},
	{Name: "f.root-servers.net.", Type: dns.TypeAAAA, Class: dns.ClassIN, TTL: 3600000, RData: dns.AAAA(netip.MustParseAddr("2001:500:2f::f"))},
	{Name: "g.root-servers.net.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 3600000, RData: netip.MustParseAddr("192.112.36.4")},
	{Name: "g.root-servers.net.", Type: dns.TypeAAAA, Class: dns.ClassIN, TTL: 3600000, RData: dns.AAAA(netip.MustParseAddr("2001:500:12::d0d"))},
	{Name: "h.root-servers.net.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 3600000, RData: netip.MustParseAddr("198.97.190.53")},
	{Name: "h.root-servers.net.", Type: dns.TypeAAAA, Class: dns.ClassIN, TTL: 3600000, RData: dns.AAAA(netip.MustParseAddr("2001:500:1::53"))},
	{Name: "i.root-servers.net.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 3600000, RData: netip.MustParseAddr("192.36.148.17")},
	{Name: "i.root-servers.net.", Type: dns.TypeAAAA, Class: dns.ClassIN, TTL: 3600000, RData: dns.AAAA(netip.MustParseAddr("2001:7fe::53"))},
	{Name: "j.root-servers.net.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 3600000, RData: netip.MustParseAddr("192.58.128.30")},
	{Name: "j.root-servers.net.", Type: dns.TypeAAAA, Class: dns.ClassIN, TTL: 3600000, RData: dns.AAAA(netip.MustParseAddr("2001:503:c27::2:30"))},
	{Name: "k.root-servers.net.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 3600000, RData: netip.MustParseAddr("193.0.14.129")},
	{Name: "k.root-servers.net.", Type: dns.TypeAAAA, Class: dns.ClassIN, TTL: 3600000, RData: dns.AAAA(netip.MustParseAddr("2001:7fd::1"))},
	{Name: "l.root-servers.net.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 3600000, RData: netip.MustParseAddr("199.7.83.42")},
	{Name: "l.root-servers.net.", Type: dns.TypeAAAA, Class: dns.ClassIN, TTL: 3600000, RData: dns.AAAA(netip.MustParseAddr("2001:500:9f::42"))},
	{Name: "m.root-servers.net.", Type: dns.TypeA, Class: dns.ClassIN, TTL: 3600000, RData: netip.MustParseAddr("202.12.27.33")},
	{Name: "m.root-servers.net.", Type: dns.TypeAAAA, Class: dns.ClassIN, TTL: 3600000, RData: dns.AAAA(netip.MustParseAddr("2001:dc3::35"))},
}

func recursiveResolver(req dns.Request) ([]byte, error) {
	if req.Question.Name == "." && req.Question.Type == dns.TypeNS {
		answers := rootServerNSRRs
		additionals := rootServers
		res, err := dns.MakeResponse(req.Header, req.Question, answers, zoneAuthorities, additionals)
		if err != nil {
			return nil, err
		}
		bytes, err := res.Bytes()
		if err != nil {
			return nil, err
		}
		return bytes, nil
	} else if req.Question.Name == "com." && req.Question.Type == dns.TypeNS {
		client := dns.Client{}
		resMsg, err := client.Do("udp", "198.41.0.4:53", req.Question.Name.String(), req.Question.Type.String(), false)
		if err != nil {
			return nil, err
		}
		res, err := dns.ParseResMsg(resMsg)
		if err != nil {
			return nil, err
		}
		res.Header.ID = req.Header.ID
		res.AnswerResourceRecords = res.AuthorityResourceRecords
		res.Header.ANCount = uint16(len(res.AnswerResourceRecords))
		res.AuthorityResourceRecords = nil
		res.Header.NSCount = 0
		res.AdditionalResourceRecords = nil
		res.Header.ARCount = 0
		bytes, err := res.Bytes()
		if err != nil {
			return nil, err
		}
		return bytes, nil
	}
	return nil, fmt.Errorf("TODO")
}

func handleConnection(conn net.PacketConn, addr net.Addr, req []byte, fn ServFunc) {
	var bytes []byte

	request, err := dns.ParseRequest(req)
	if err != nil {
		log.Print("[error] ", err)
		goto Error
	}

	bytes, err = fn(*request)
	if err != nil {
		log.Print("[error] ", err)
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

	conn, err := net.ListenPacket("udp", os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	fn := recursiveResolver
	if len(os.Args) == 3 {
		loadZonefiles(os.Args[2])
		fn = authoritativeServer
	}

	for {
		buf := make([]byte, 1500)
		n, addr, err := conn.ReadFrom(buf[:])
		if err != nil {
			log.Print("[error] ", err)
			continue
		}
		go handleConnection(conn, addr, buf[:n], fn)
	}
}
