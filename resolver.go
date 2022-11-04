package dns

import (
	"fmt"
	"time"
)

var RootServerNSRRs []ResourceRecord

var RootServers []ResourceRecord

var rootServer string

func LoadRootZone(path string) error {
	zone, err := ReadZonefile(path)
	if err != nil {
		return err
	}
	for _, rr := range zone.Records {
		if rr.Type == TypeNS {
			RootServerNSRRs = append(RootServerNSRRs, rr)
		} else {
			if rootServer == "" && rr.Type == TypeA {
				rootServer = rr.RData.String()
			}
			RootServers = append(RootServers, rr)
		}
	}
	return nil
}

func Resolve(question Question, client *Client, cache *Cache) ([]ResourceRecord, error) {
	Log.Debugf("Resolve: question: %v", question)
	nameServer := rootServer
	if client == nil {
		client = &Client{Limit: 20}
	}
	if cache == nil {
		cache = NewCache()
	}

	now := time.Now().Unix()
	val, ttl, ok := cache.Get(question, now)
	if ok {
		// cache hit
		Log.Debugf("Resolve: cache hit")
		var result []ResourceRecord
		for _, rr := range val.([]ResourceRecord) {
			rr.TTL = TTL(ttl)
			result = append(result, rr)
		}
		return result, nil
	} else {
		// cache miss
		Log.Debugf("Resolve: cache miss")
	}

	for {
		Log.Debugf("Resolve: nameServer: %v", nameServer)
		res, err := client.Do("udp", nameServer+":53", question, false, false)
		if err != nil {
			return nil, err
		}
		if len(res.AnswerResourceRecords) != 0 {
			var ttl int64 = 86400 // 1 day
			for _, v := range res.AnswerResourceRecords {
				if int64(v.TTL) < ttl {
					ttl = int64(v.TTL)
				}
			}
			cache.Set(question, res.AnswerResourceRecords, now+ttl)
			Log.Debugf("Resolve: cache store")
			return res.AnswerResourceRecords, nil
		}
		if len(res.AdditionalResourceRecords) != 0 {
			var founds []ResourceRecord
			for _, adrr := range res.AdditionalResourceRecords {
				if adrr.Name == question.Name && adrr.Type == question.Type {
					founds = append(founds, adrr)
				}
			}
			if len(founds) != 0 {
				return founds, nil
			}
		}
		if len(res.AuthorityResourceRecords) != 0 {
			nsname := res.AuthorityResourceRecords[0].RData.String()
			Log.Debugf("Resolve: res.AuthorityResourceRecords[0]: %v", res.AuthorityResourceRecords[0])
			if len(res.AdditionalResourceRecords) != 0 {
				var found *ResourceRecord
				for _, adrr := range res.AdditionalResourceRecords {
					if nsname == adrr.Name.String() && adrr.Type == TypeA {
						found = &adrr
						break
					}
				}
				if found != nil {
					Log.Debugf("Resolve: found: %v", found)
					nameServer = found.RData.String()
					continue
				}
			}

			rrs, err := Resolve(Question{Name(nsname), TypeA, ClassIN}, client, cache)
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
