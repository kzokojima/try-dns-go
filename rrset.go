package dns

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
