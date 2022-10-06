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
				type_ rrType
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
				rdata = addr
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
					preference,
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
				rdata = NS(name)
			} else if fields[0] == "CNAME" {
				// TODO
				continue
			} else if fields[0] == "TXT" {
				// TODO
				continue
			} else if fields[0] == "AAAA" {
				// TODO
				continue
			} else {
				return nil, fmt.Errorf("invalid format: %v", fields)
			}

			zone.Records = append(zone.Records, ResourceRecord{
				Name(name),
				type_,
				class,
				TTL(ttl),
				rdata,
			})
		}
	}

	return zone, nil
}
