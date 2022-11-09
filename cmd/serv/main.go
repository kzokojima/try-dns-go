package main

import (
	"flag"
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
		zoneResourceRecords[key] = append(zoneResourceRecords[key], v)
	}
	key := dns.Question{Name: dns.Name(zone.Origin), Type: dns.TypeNS, Class: dns.ClassIN}
	zoneAuthorities = zoneResourceRecords[key]
	return nil
}

func findResourceRecords(name dns.Name, type_ dns.Type, class dns.Class) []dns.ResourceRecord {
	return zoneResourceRecords[dns.Question{Name: dns.Name(name), Type: type_, Class: class}]
}

func getAdditionals(answers []dns.ResourceRecord) []dns.ResourceRecord {
	var results1, results2 []dns.ResourceRecord
	for _, answer := range answers {
		if answer.Type == dns.TypeMX {
			rrs := findResourceRecords(dns.Name(answer.RData.(dns.MX).Exchange), dns.TypeA, dns.ClassIN)
			results1 = append(results1, rrs...)
			rrs = findResourceRecords(dns.Name(answer.RData.(dns.MX).Exchange), dns.TypeAAAA, dns.ClassIN)
			results2 = append(results2, rrs...)
		}
	}
	return append(results1, results2...)
}

type ServFunc func(dns.Request) (*dns.Response, error)

func authoritativeServer(req dns.Request) (*dns.Response, error) {
	var answers, additionals []dns.ResourceRecord

	answers, ok := zoneResourceRecords[req.Question]
	if ok {
		additionals = getAdditionals(answers)
	} else {
		// CNAME
		answers = findResourceRecords(req.Question.Name, dns.TypeCNAME, dns.ClassIN)
		if len(answers) == 1 {
			cname := answers[0]
			rrs := findResourceRecords(cname.RData.(dns.CNAME), req.Question.Type, dns.ClassIN)
			answers = append(answers, rrs...)
		} else {
			return dns.MakeResponse(req.Header.ID,
				dns.MakeHeaderFields(req.Header.Opcode(), dns.QR, dns.NXDOMAIN),
				req.Question, nil, nil, nil)
		}
	}
	return dns.MakeResponse(req.Header.ID,
		dns.MakeHeaderFields(req.Header.Opcode(), dns.QR, dns.AA, dns.NOERROR),
		req.Question, answers, zoneAuthorities, additionals)
}

var cache = dns.NewCache()

func resolver(req dns.Request) (*dns.Response, error) {
	if req.Question.Name == "." && req.Question.Type == dns.TypeNS {
		// root
		answers := dns.RootServerNSRRs
		additionals := dns.RootServers
		return dns.MakeResponse(req.Header.ID,
			dns.MakeHeaderFields(req.Header.Opcode(), dns.QR, dns.AA, dns.RD, dns.RA, dns.NOERROR),
			req.Question, answers, zoneAuthorities, additionals)
	}

	rrs, err := dns.Resolve(req.Question, nil, cache)
	if err != nil {
		return dns.MakeResponse(req.Header.ID,
			dns.MakeHeaderFields(req.Header.Opcode(), dns.QR, dns.RD, dns.RA, dns.NXDOMAIN),
			req.Question, nil, nil, nil)
	}
	return dns.MakeResponse(req.Header.ID,
		dns.MakeHeaderFields(req.Header.Opcode(), dns.QR, dns.RD, dns.RA, dns.NOERROR),
		req.Question, rrs, nil, nil)
}

func handleConnection(conn net.PacketConn, addr net.Addr, req []byte, fn ServFunc) {
	var (
		bytes    []byte
		err      error
		request  *dns.Request
		response *dns.Response
	)

	request, err = dns.ParseRequest(req)
	if err != nil {
		dns.Log.Error(err)
		return
	}

	response, err = fn(*request)
	if err != nil {
		dns.Log.Error(err)
		return
	}
	bytes, err = response.Bytes()
	if err != nil {
		dns.Log.Error(err)
		return
	}

	conn.WriteTo(bytes, addr)
	dns.Log.Infof("%v %v", addr.String(), len(bytes))
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
