package dns

import (
	"strings"
)

type RRSet struct {
	Name
	Type
	Class
	TTL
	RDatas []RData
}

func (rrSet *RRSet) ResourceRecords() []ResourceRecord {
	var rrs []ResourceRecord
	for _, v := range rrSet.RDatas {
		rrs = append(rrs, ResourceRecord{rrSet.Name, rrSet.Type, rrSet.Class, rrSet.TTL, v})
	}
	return rrs
}

func (rrSet *RRSet) String() string {
	var result []string
	for _, rr := range rrSet.ResourceRecords() {
		result = append(result, rr.String())
	}
	return strings.Join(result, "\n") + "\n"
}

type RRSets map[Question]*RRSet

func NewRRSets(rrs []ResourceRecord) RRSets {
	rrSets := make(RRSets)
	for _, v := range rrs {
		key := Question{v.Name, v.Type, v.Class}
		rrSet, ok := rrSets[key]
		if !ok {
			rrSet = new(RRSet)
			rrSet.Name = v.Name
			rrSet.Type = v.Type
			rrSet.Class = v.Class
			rrSet.TTL = v.TTL
			rrSets[key] = rrSet
		}
		if rrSet.TTL > v.TTL {
			rrSet.TTL = v.TTL
		}
		rrSet.RDatas = append(rrSet.RDatas, v.RData)
	}
	return rrSets
}

func (rrSets *RRSets) String() string {
	var result []string
	for _, rrSets := range *rrSets {
		result = append(result, rrSets.String())
	}
	return strings.Join(result, "")
}
