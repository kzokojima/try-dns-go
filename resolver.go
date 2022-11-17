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

func Resolve(question Question, client Client, cache *Cache) ([]ResourceRecord, error) {
	Log.Debugf("Resolve: question: %v", question)
	nameServer := rootServer
	if client == nil {
		client = &BasicClient{Limit: 20}
	}
	if cache == nil {
		cache = NewCache()
	}

	now := time.Now().Unix()
	val, ttl, ok := cache.Get(question, now)
	if ok {
		// cache hit
		Log.Debugf("Resolve: cache hit")
		rrSet := *val.(*RRSet)
		rrSet.TTL = TTL(ttl)
		return rrSet.ResourceRecords(), nil
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
		answerRRSets := NewRRSets(res.AnswerResourceRecords)
		for k, v := range answerRRSets {
			cache.Set(k, v, now+int64(v.TTL))
			Log.Debugf("Resolve: cache store: %v", k)
		}
		authorityRRSets := NewRRSets(res.AuthorityResourceRecords)
		for k, v := range authorityRRSets {
			cache.Set(k, v, now+int64(v.TTL))
			Log.Debugf("Resolve: cache store: %v", k)
		}
		additionalRRSets := NewRRSets(res.AdditionalResourceRecords)
		for k, v := range additionalRRSets {
			cache.Set(k, v, now+int64(v.TTL))
			Log.Debugf("Resolve: cache store: %v", k)
		}

		if len(res.AnswerResourceRecords) != 0 {
			return res.AnswerResourceRecords, nil
		}

		rrSet, ok := additionalRRSets[question]
		if ok {
			return rrSet.ResourceRecords(), nil
		}

		if len(res.AuthorityResourceRecords) != 0 {
			Log.Debugf("Resolve: res.AuthorityResourceRecords[0]: %v", res.AuthorityResourceRecords[0])
			nsname := res.AuthorityResourceRecords[0].RData.(NS)
			question := Question{nsname, TypeA, ClassIN}
			rrSet, ok := additionalRRSets[question]
			if ok {
				rrs := rrSet.ResourceRecords()
				Log.Debugf("Resolve: found: %v", rrs[0])
				nameServer = rrs[0].RData.String()
				continue
			}

			rrs, err := Resolve(question, client, cache)
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
