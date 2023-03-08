package dns

import (
	"fmt"
	"time"
)

var RootServerNSRRs []ResourceRecord

var RootServers []ResourceRecord

var rootServer string

var rootDS *DS

func SetUpResolver(zone, rootAnchorsXML string) error {
	var err error
	err = LoadRootZone(zone)
	if err != nil {
		return err
	}
	rootDS, err = getRootAnchorDS(rootAnchorsXML)
	if err != nil {
		return err
	}
	return nil
}

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

func Resolve(question Question, qNameMin bool, dnssec bool, client Client, cache *Cache) (rrs []ResourceRecord, ad bool, err error) {
	edns := dnssec
	Log.Debugf("Resolve: question: %v", question)
	nameServer := rootServer
	var zoneName string
	dnssecDSs := []DS{*rootDS}
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
		return rrSet.ResourceRecords(), false, nil
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
		res, err := client.Do("udp", nameServer+":53", pquestion, false, edns, dnssec)
		if err != nil {
			return nil, false, err
		}
		answerRRSets := NewRRSets(res.AnswerResourceRecords)
		authorityRRSets := NewRRSets(res.AuthorityResourceRecords)
		additionalRRSets := NewRRSets(res.AdditionalResourceRecords)
		if dnssec {
			dsRRSet, ok := authorityRRSets[Question{pquestion.Name, TypeDS, ClassIN}]
			if ok {
				rrsigRRSet := authorityRRSets[Question{pquestion.Name, TypeRRSIG, ClassIN}]
				zsk, err := getZSK(pquestion.Name.parent(), nameServer, dnssecDSs, client)
				if err != nil {
					return nil, false, fmt.Errorf("failed getZSK, pquestion: %v, %w", pquestion, err)
				}
				Log.Debugf("Resolve: verifyRRSet: %v, %x,  %v, %v", pquestion, zsk, dsRRSet, rrsigRRSet.RDatas[0].(RRSIG))
				err = verifyRRSet(zsk, dsRRSet, rrsigRRSet.RDatas[0].(RRSIG))
				if err != nil {
					return nil, false, fmt.Errorf("failed verifyRRSet, pquestion: %v, %w", pquestion, err)
				}
				dnssecDSs = nil
				for _, v := range dsRRSet.RDatas {
					dnssecDSs = append(dnssecDSs, v.(DS))
				}
			}
		}
		storeRRSets(answerRRSets, cache, now)
		storeRRSets(authorityRRSets, cache, now)
		storeRRSets(additionalRRSets, cache, now)

		if len(res.AnswerResourceRecords) != 0 && pquestion == question {
			return res.AnswerResourceRecords, false, nil
		}

		rrSet, ok := additionalRRSets[question]
		if ok {
			return rrSet.ResourceRecords(), false, nil
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
							zoneName = pname
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
					return nil, false, fmt.Errorf("ERR")
				}
			}
			question := Question{nsname, TypeA, ClassIN}
			rrs, _, err := Resolve(question, qNameMin, dnssec, client, cache)
			if err != nil {
				return nil, false, err
			}
			if len(rrs) == 0 {
				return nil, false, fmt.Errorf("ERR")
			}
			nameServer = rrs[0].RData.String()
			zoneName = pname
			continue
		}
		return nil, false, fmt.Errorf("ERR")
	}

	Log.Debugf("Resolve: send request: @%v %v", nameServer, question)
	res, err := client.Do("udp", nameServer+":53", question, false, edns, dnssec)
	if err != nil {
		return nil, false, err
	}
	if len(res.AnswerResourceRecords) != 0 {
		answerRRSets := NewRRSets(res.AnswerResourceRecords)

		if dnssec {
			rrSet, ok := answerRRSets[question]
			if ok {
				rrsigRRSet := answerRRSets[Question{question.Name, TypeRRSIG, question.Class}]
				zsk, err := getZSK(Name(zoneName), nameServer, dnssecDSs, client)
				if err != nil {
					return nil, false, fmt.Errorf("failed getZSK, question: %v, %w", question, err)
				}
				Log.Debugf("Resolve: verifyRRSet: %v, %x, %v,  %v", question, zsk, rrSet, rrsigRRSet.RDatas[0].(RRSIG))
				err = verifyRRSet(zsk, rrSet, rrsigRRSet.RDatas[0].(RRSIG))
				if err != nil {
					return nil, false, fmt.Errorf("failed verifyRRSet, question: %v, %w", question, err)
				}
				ad = true
			}
		}

		storeRRSets(answerRRSets, cache, now)
		Log.Debugf("Resolve: return: %v", res.AnswerResourceRecords)
		return res.AnswerResourceRecords, ad, nil
	}

	return nil, false, fmt.Errorf("ERR2")
}

func storeRRSets(rrSets RRSets, cache *Cache, now int64) {
	for k, v := range rrSets {
		cache.Set(k, v, now+int64(v.TTL))
	}
}
