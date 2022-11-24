package dns

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

type Type uint16

const (
	TypeA      Type = 1
	TypeNS     Type = 2
	TypeCNAME  Type = 5
	TypeSOA    Type = 6
	TypePTR    Type = 12
	TypeMX     Type = 15
	TypeTXT    Type = 16
	TypeAAAA   Type = 28
	TypeOPT    Type = 41
	TypeDS     Type = 43
	TypeRRSIG  Type = 46
	TypeNSEC   Type = 47
	TypeDNSKEY Type = 48
)

var typeTexts = map[Type]string{
	TypeA:      "A",
	TypeNS:     "NS",
	TypeCNAME:  "CNAME",
	TypeSOA:    "SOA",
	TypePTR:    "PTR",
	TypeMX:     "MX",
	TypeTXT:    "TXT",
	TypeAAAA:   "AAAA",
	TypeOPT:    "OPT",
	TypeDS:     "DS",
	TypeRRSIG:  "RRSIG",
	TypeNSEC:   "NSEC",
	TypeDNSKEY: "DNSKEY",
}

func typeFromString(s string) (Type, error) {
	for type_, text := range typeTexts {
		if s == text {
			return type_, nil
		}
	}
	return 0, fmt.Errorf("invalid type text")
}

func (t Type) String() string {
	return typeTexts[t]
}

type A netip.Addr

func (a A) MarshalBinary(msg []byte) (data []byte, err error) {
	return netip.Addr(a).AsSlice(), nil
}

func (a A) String() string {
	return netip.Addr(a).String()
}

type NS = Name

type CNAME = Name

type SOA struct {
	mname   string
	rname   string
	serial  uint32
	refresh uint32
	retry   uint32
	expire  uint32
	minimum uint32
}

func (soa SOA) MarshalBinary(msg []byte) (data []byte, err error) {
	// TODO
	return
}

func (soa SOA) String() string {
	return fmt.Sprintf("%v %v %v %v %v %v %v", soa.mname, soa.rname, soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum)
}

type MX struct {
	Preference uint16
	Exchange   string
}

func (mx MX) MarshalBinary(msg []byte) (data []byte, err error) {
	name, err := encodeName(mx.Exchange, msg)
	if err != nil {
		return nil, err
	}
	data = make([]byte, 2+len(name))
	binary.BigEndian.PutUint16(data, mx.Preference)
	copy(data[2:], name)
	return
}

func (mx MX) String() string {
	return fmt.Sprint(mx.Preference, " ", mx.Exchange)
}

type TXT string

func newTxt(fields []string) TXT {
	return TXT(strings.Join(fields, "\x00"))
}

func (txt TXT) MarshalBinary(msg []byte) (data []byte, err error) {
	return encodeTexts(strings.Split(string(txt), "\x00"))
}

func (txt TXT) String() string {
	return strings.ReplaceAll(string(txt), "\x00", " ")
}

type AAAA netip.Addr

func newAAAA(fields []string) (*AAAA, error) {
	addr, err := netip.ParseAddr(fields[0])
	if err != nil {
		return nil, err
	}
	if !addr.Is6() {
		return nil, fmt.Errorf("invalid IPv4 addr")
	}
	aaaa := AAAA(addr)
	return &aaaa, nil
}

func (aaaa AAAA) MarshalBinary(msg []byte) (data []byte, err error) {
	return netip.Addr(aaaa).AsSlice(), nil
}

func (aaaa AAAA) String() string {
	return netip.Addr(aaaa).String()
}

type DS struct {
	keyTag     uint16
	algo       byte
	digestType byte
	digest     []byte
}

func newDS(fields []string) (*DS, error) {
	v0, err := strconv.Atoi(fields[0])
	if err != nil {
		return nil, err
	}
	v1, err := strconv.Atoi(fields[1])
	if err != nil {
		return nil, err
	}
	v2, err := strconv.Atoi(fields[2])
	if err != nil {
		return nil, err
	}
	return &DS{
		uint16(v0),
		byte(v1),
		byte(v2),
		[]byte(fields[3]),
	}, nil
}

func (ds DS) MarshalBinary(msg []byte) (data []byte, err error) {
	// TODO
	return
}
func (ds DS) String() string {
	return fmt.Sprintf("%v %v %v %X", ds.keyTag, ds.algo, ds.digestType, ds.digest)
}

type RRSIG struct {
	typeCovered         string
	algo                byte
	labels              byte
	originalTtl         uint32
	signatureExpiration string
	signatureInception  string
	keyTag              uint16
	signerName          string
	signature           string
}

func newRRSIG(fields []string) (*RRSIG, error) {
	v1, err := strconv.Atoi(fields[1])
	if err != nil {
		return nil, err
	}
	v2, err := strconv.Atoi(fields[2])
	if err != nil {
		return nil, err
	}
	v3, err := strconv.Atoi(fields[3])
	if err != nil {
		return nil, err
	}
	v6, err := strconv.Atoi(fields[6])
	if err != nil {
		return nil, err
	}
	return &RRSIG{
		fields[0],
		byte(v1),
		byte(v2),
		uint32(v3),
		fields[4],
		fields[5],
		uint16(v6),
		fields[7],
		fields[8],
	}, nil
}

func (rrsig RRSIG) MarshalBinary(msg []byte) (data []byte, err error) {
	// TODO
	return
}

func (rrsig RRSIG) String() string {
	return fmt.Sprintf("%v %v %v %v %v %v %v %v %v",
		rrsig.typeCovered, rrsig.algo, rrsig.labels, rrsig.originalTtl,
		rrsig.signatureExpiration, rrsig.signatureInception,
		rrsig.keyTag, rrsig.signerName, rrsig.signature)
}

type NSEC struct {
	nextDomainName string
	typeTexts      string
}

func newNSEC(fields []string) (*NSEC, error) {
	return &NSEC{
		fields[0],
		fields[1],
	}, nil
}

func (nsec NSEC) MarshalBinary(msg []byte) (data []byte, err error) {
	// TODO
	return
}

func (nsec NSEC) String() string {
	return fmt.Sprintf("%v %v", nsec.nextDomainName, nsec.typeTexts)
}

type DNSKEY struct {
	flags uint16
	proto byte
	algo  byte
	key   string
}

func newDNSKEY(fields []string) (*DNSKEY, error) {
	v0, err := strconv.Atoi(fields[0])
	if err != nil {
		return nil, err
	}
	v1, err := strconv.Atoi(fields[1])
	if err != nil {
		return nil, err
	}
	v2, err := strconv.Atoi(fields[2])
	if err != nil {
		return nil, err
	}
	return &DNSKEY{
		uint16(v0),
		byte(v1),
		byte(v2),
		fields[3],
	}, nil
}

func (dnskey DNSKEY) MarshalBinary(msg []byte) (data []byte, err error) {
	// TODO
	return
}

func (dnskey DNSKEY) String() string {
	return fmt.Sprintf("%v %v %v %v", dnskey.flags, dnskey.proto, dnskey.algo, dnskey.key)
}
