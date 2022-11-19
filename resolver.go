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

const QNameMinType = TypeNS

func Resolve(question Question, qNameMin bool, client Client, cache *Cache) ([]ResourceRecord, error) {
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

	// find name server
	domains := append(question.Name.ancestors(), question.Name.String())
LOOP:
	for _, pname := range domains {
		pquestion := question
		if qNameMin {
			pquestion = Question{Name(pname), QNameMinType, ClassIN}
		}
		Log.Debugf("Resolve: send request: @%v %v", nameServer, pquestion)
		res, err := client.Do("udp", nameServer+":53", pquestion, false, false)
		if err != nil {
			return nil, err
		}
		answerRRSets := NewRRSets(res.AnswerResourceRecords)
		authorityRRSets := NewRRSets(res.AuthorityResourceRecords)
		additionalRRSets := NewRRSets(res.AdditionalResourceRecords)
		storeRRSets(answerRRSets, cache, now)
		storeRRSets(authorityRRSets, cache, now)
		storeRRSets(additionalRRSets, cache, now)

		if len(res.AnswerResourceRecords) != 0 && pquestion == question {
			return res.AnswerResourceRecords, nil
		}

		rrSet, ok := additionalRRSets[question]
		if ok {
			return rrSet.ResourceRecords(), nil
		}

		if len(res.AuthorityResourceRecords) != 0 {
			for _, authorityRRSet := range authorityRRSets {
				// find glue record
				for _, v := range authorityRRSet.RDatas {
					nsname, ok := v.(NS)
					if ok {
						rrSet, ok := additionalRRSets[Question{nsname, TypeA, ClassIN}]
						if ok {
							rrs := rrSet.ResourceRecords()
							nameServer = rrs[0].RData.String()
							continue LOOP
						}
					}
				}
			}

			Log.Debugf("Resolve: res.AuthorityResourceRecords[0]: %v", res.AuthorityResourceRecords[0])
			nsname, ok := res.AuthorityResourceRecords[0].RData.(NS)
			if !ok {
				if qNameMin {
					continue
				} else {
					return nil, fmt.Errorf("ERR")
				}
			}
			question := Question{nsname, TypeA, ClassIN}
			rrs, err := Resolve(question, qNameMin, client, cache)
			if err != nil {
				return nil, err
			}
			if len(rrs) == 0 {
				return nil, fmt.Errorf("ERR")
			}
			nameServer = rrs[0].RData.String()
			continue
		}
		return nil, fmt.Errorf("ERR")
	}

	Log.Debugf("Resolve: send request1: @%v %v", nameServer, question)
	res, err := client.Do("udp", nameServer+":53", question, false, false)
	if err != nil {
		return nil, err
	}
	if len(res.AnswerResourceRecords) != 0 {
		answerRRSets := NewRRSets(res.AnswerResourceRecords)
		storeRRSets(answerRRSets, cache, now)
		Log.Debugf("Resolve: return: %v", res.AnswerResourceRecords)
		return res.AnswerResourceRecords, nil
	}

	return nil, fmt.Errorf("ERR2")
}

func storeRRSets(rrSets RRSets, cache *Cache, now int64) {
	for k, v := range rrSets {
		cache.Set(k, v, now+int64(v.TTL))
	}
}
