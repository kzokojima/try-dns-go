package dns

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

type Zone struct {
	Origin  string
	TTL     int
	Records []ResourceRecord
}

func ReadZonefile(path string) (*Zone, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	zone := new(Zone)

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], ";") {
			continue
		}
		if fields[0] == "$ORIGIN" {
			if !strings.HasSuffix(fields[1], ".") {
				return nil, fmt.Errorf("$ORIGIN: invalid format")
			}
			zone.Origin = fields[1]
		} else if fields[0] == "$TTL" {
			zone.TTL, err = strconv.Atoi(fields[1])
			if err != nil {
				return nil, err
			}
		} else {
			var (
				name  string
				ttl   int
				class class = ClassIN
			)

			// name
			if fields[0] == "@" {
				name = zone.Origin
			} else if strings.HasSuffix(fields[0], ".") {
				name = fields[0]
			} else {
				name = fields[0] + "." + zone.Origin
			}
			fields = fields[1:]

			// TTL
			ttl, err := strconv.Atoi(fields[0])
			if err != nil {
				ttl = zone.TTL
			} else {
				fields = fields[1:]
			}

			// class
			if fields[0] == "IN" {
				class = ClassIN
				fields = fields[1:]
			}

			var (
				type_ Type
				rdata RData
			)

			if fields[0] == "A" && len(fields) == 2 {
				addr, err := netip.ParseAddr(fields[1])
				if err != nil {
					return nil, err
				}
				if !addr.Is4() {
					return nil, fmt.Errorf("invalid IPv4 addr")
				}
				type_ = TypeA
				rdata = A(addr)
			} else if fields[0] == "MX" && len(fields) == 3 {
				preference, err := strconv.Atoi(fields[1])
				if err != nil {
					return nil, err

				}
				exchange := fields[2]
				if !strings.HasSuffix(exchange, ".") {
					exchange = fields[2] + "." + zone.Origin
				}
				type_ = TypeMX
				rdata = MX{
					uint16(preference),
					exchange,
				}
			} else if fields[0] == "SOA" {
				// TODO
				continue
			} else if fields[0] == "NS" && len(fields) == 2 {
				name := fields[1]
				if !strings.HasSuffix(name, ".") {
					name = fields[1] + "." + zone.Origin
				}
				type_ = TypeNS
				rdata = NS(strings.ToLower(name))
			} else if fields[0] == "CNAME" && len(fields) == 2 {
				name := fields[1]
				if name == "@" {
					name = zone.Origin
				} else if !strings.HasSuffix(name, ".") {
					name = fields[1] + "." + zone.Origin
				}
				type_ = TypeCNAME
				rdata = CNAME(name)
			} else if fields[0] == "TXT" {
				type_ = TypeTXT
				rdata = newTxt(fields[1:])
			} else if fields[0] == "AAAA" && len(fields) == 2 {
				type_ = TypeAAAA
				aaaa, err := newAAAA(fields[1:])
				if err != nil {
					return nil, err
				}
				rdata = *aaaa
			} else {
				m := map[string]struct {
					Type
					fn func([]string) (RData, error)
				}{
					"DS":     {TypeDS, func(s []string) (RData, error) { return newDS(s) }},
					"RRSIG":  {TypeRRSIG, func(s []string) (RData, error) { return newRRSIG(s) }},
					"DNSKEY": {TypeDNSKEY, func(s []string) (RData, error) { return newDNSKEY(s) }},
					"NSEC":   {TypeNSEC, func(s []string) (RData, error) { return newNSEC(s) }},
				}
				v, ok := m[fields[0]]
				if !ok {
					return nil, fmt.Errorf("invalid format: %v", fields)
				}
				type_ = v.Type
				data, err := v.fn(fields[1:])
				if err != nil {
					return nil, fmt.Errorf("invalid format: %v", fields)
				}
				rdata = data
			}

			zone.Records = append(zone.Records, ResourceRecord{
				Name(strings.ToLower(name)),
				type_,
				class,
				TTL(ttl),
				rdata,
			})
		}
	}

	return zone, nil
}
