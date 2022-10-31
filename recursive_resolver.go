package dns

import (
	"fmt"
	"log"
)

var RootServerNSRRs []ResourceRecord

var RootServers []ResourceRecord

// a.root-servers.net
var rootServer = "198.41.0.4"

func LoadRootZone(path string) error {
	zone, err := ReadZonefile(path)
	if err != nil {
		return err
	}
	for _, rr := range zone.Records {
		if rr.Type == TypeNS {
			RootServerNSRRs = append(RootServerNSRRs, rr)
		} else {
			RootServers = append(RootServers, rr)
		}
	}
	return nil
}

func RecursiveResolve(name string, type_ string, client *Client) ([]ResourceRecord, error) {
	log.Printf("[debug] RecursiveResolve: %v %v", name, type_)
	nameServer := rootServer
	if client == nil {
		client = &Client{Limit: 20}
	}

	for {
		log.Printf("[debug] RecursiveResolve: nameServer: @%v %v %v", nameServer, name, type_)
		res, err := client.Do("udp", nameServer+":53", name, type_, false, false)
		if err != nil {
			return nil, err
		}
		if len(res.AnswerResourceRecords) != 0 {
			return res.AnswerResourceRecords, nil
		}
		if len(res.AdditionalResourceRecords) != 0 {
			var founds []ResourceRecord
			for _, adrr := range res.AdditionalResourceRecords {
				if adrr.Name.String() == name && adrr.Type.String() == type_ {
					founds = append(founds, adrr)
				}
			}
			if len(founds) != 0 {
				return founds, nil
			}
		}
		if len(res.AuthorityResourceRecords) != 0 {
			nsname := res.AuthorityResourceRecords[0].RData.String()
			log.Printf("[debug] RecursiveResolve: res.AuthorityResourceRecords[0]: %v", res.AuthorityResourceRecords[0])
			if len(res.AdditionalResourceRecords) != 0 {
				var found *ResourceRecord
				for _, adrr := range res.AdditionalResourceRecords {
					if nsname == adrr.Name.String() && adrr.Type == TypeA {
						found = &adrr
						break
					}
				}
				if found != nil {
					log.Printf("[debug] RecursiveResolve: found: %v", found)
					nameServer = found.RData.String()
					continue
				}
			}

			rrs, err := RecursiveResolve(nsname, "A", client)
			if err != nil {
				return nil, err
			}
			if len(rrs) == 0 {
				return nil, fmt.Errorf("ERR")
			}
			nameServer = rrs[0].RData.String()
		} else {
			return nil, fmt.Errorf("ERR")
		}
	}
}
