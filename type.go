package dns

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
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
	TypeNSEC3  Type = 50
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
	TypeNSEC3:  "NSEC3",
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

func mustParseA(s string) A {
	return A(netip.MustParseAddr(s))
}

func (a A) MarshalBinary(msg []byte) (data []byte, err error) {
	return netip.Addr(a).AsSlice(), nil
}

func (a A) String() string {
	return netip.Addr(a).String()
}

type NS = Name

type CNAME = Name

type SOA struct {
	mname   Name
	rname   Name
	serial  uint32
	refresh uint32
	retry   uint32
	expire  uint32
	minimum uint32
}

func newSOA(fields []string) (*SOA, error) {
	v2, err := strconv.Atoi(fields[2])
	if err != nil {
		return nil, err
	}
	v3, err := strconv.Atoi(fields[3])
	if err != nil {
		return nil, err
	}
	v4, err := strconv.Atoi(fields[4])
	if err != nil {
		return nil, err
	}
	v5, err := strconv.Atoi(fields[5])
	if err != nil {
		return nil, err
	}
	v6, err := strconv.Atoi(fields[6])
	if err != nil {
		return nil, err
	}
	return &SOA{
		Name(fields[0]),
		Name(fields[1]),
		uint32(v2),
		uint32(v3),
		uint32(v4),
		uint32(v5),
		uint32(v6),
	}, nil
}

func (soa SOA) MarshalBinary(msg []byte) (data []byte, err error) {
	mname, err := encodeName(soa.mname.String(), msg)
	if err != nil {
		return nil, err
	}
	rname, err := encodeName(soa.rname.String(), msg)
	if err != nil {
		return nil, err
	}
	data = make([]byte, 20+len(mname)+len(rname))
	copy(data, mname)
	copy(data[len(mname):], rname)
	binary.BigEndian.PutUint32(data[len(mname)+len(rname):], soa.serial)
	binary.BigEndian.PutUint32(data[len(mname)+len(rname)+4:], soa.refresh)
	binary.BigEndian.PutUint32(data[len(mname)+len(rname)+8:], soa.retry)
	binary.BigEndian.PutUint32(data[len(mname)+len(rname)+12:], soa.expire)
	binary.BigEndian.PutUint32(data[len(mname)+len(rname)+16:], soa.minimum)
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
	v3 := strings.ReplaceAll(fields[3], " ", "")
	v3b := make([]byte, len(v3)/2)
	_, err = fmt.Sscanf(v3, "%X", &v3b)
	if err != nil {
		return nil, err
	}
	return &DS{
		uint16(v0),
		byte(v1),
		byte(v2),
		v3b,
	}, nil
}

func mustParseDS(s string) DS {
	ds, _ := newDS(strings.SplitN(s, " ", 4))
	return *ds
}

func (ds DS) MarshalBinary(msg []byte) (data []byte, err error) {
	data = make([]byte, 4+len(ds.digest))
	binary.BigEndian.PutUint16(data, ds.keyTag)
	data[2] = ds.algo
	data[3] = ds.digestType
	copy(data[4:], ds.digest)
	return
}

func (ds DS) String() string {
	return fmt.Sprintf("%v %v %v %X", ds.keyTag, ds.algo, ds.digestType, ds.digest)
}

type RRSIG struct {
	TypeCovered         Type
	Algo                byte
	Labels              byte
	OriginalTtl         uint32
	SignatureExpiration uint32
	SignatureInception  uint32
	KeyTag              uint16
	SignerName          Name
	Signature           []byte
}

const TimeLayout = "20060102150405"

func newRRSIG(fields []string) (*RRSIG, error) {
	v0, err := typeFromString(fields[0])
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
	v3, err := strconv.Atoi(fields[3])
	if err != nil {
		return nil, err
	}
	v4, err := time.Parse(TimeLayout, fields[4])
	if err != nil {
		return nil, err
	}
	v5, err := time.Parse(TimeLayout, fields[5])
	if err != nil {
		return nil, err
	}
	v6, err := strconv.Atoi(fields[6])
	if err != nil {
		return nil, err
	}
	v8, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(fields[8], " ", ""))
	if err != nil {
		return nil, err
	}
	return &RRSIG{
		v0,
		byte(v1),
		byte(v2),
		uint32(v3),
		uint32(v4.Unix()),
		uint32(v5.Unix()),
		uint16(v6),
		Name(fields[7]),
		v8,
	}, nil
}

func mustParseRRSIG(s string) RRSIG {
	rrsig, _ := newRRSIG(strings.SplitN(s, " ", 9))
	return *rrsig
}

func (rrsig RRSIG) MarshalBinary(msg []byte) (data []byte, err error) {
	data, err = rrsig.MarshalBinaryWithoutSig()
	if err != nil {
		return
	}
	data = append(data, rrsig.Signature...)
	return
}

func (rrsig RRSIG) MarshalBinaryWithoutSig() (data []byte, err error) {
	signerName, err := encodeName(rrsig.SignerName.String(), nil)
	if err != nil {
		return nil, err
	}
	data = make([]byte, 18+len(signerName))
	binary.BigEndian.PutUint16(data, uint16(rrsig.TypeCovered))
	data[2] = rrsig.Algo
	data[3] = rrsig.Labels
	binary.BigEndian.PutUint32(data[4:], rrsig.OriginalTtl)
	binary.BigEndian.PutUint32(data[8:], rrsig.SignatureExpiration)
	binary.BigEndian.PutUint32(data[12:], rrsig.SignatureInception)
	binary.BigEndian.PutUint16(data[16:], rrsig.KeyTag)
	copy(data[18:], signerName)
	return
}

func (rrsig RRSIG) String() string {
	return fmt.Sprintf("%v %v %v %v %v %v %v %v %v",
		rrsig.TypeCovered, rrsig.Algo, rrsig.Labels, rrsig.OriginalTtl,
		time.Unix(int64(rrsig.SignatureExpiration), 0).UTC().Format(TimeLayout),
		time.Unix(int64(rrsig.SignatureInception), 0).UTC().Format(TimeLayout),
		rrsig.KeyTag, rrsig.SignerName,
		base64.StdEncoding.EncodeToString(rrsig.Signature))
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
	Flags uint16
	Proto byte
	Algo  byte
	Key   []byte
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
	key, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(fields[3], " ", ""))
	if err != nil {
		return nil, err
	}
	return &DNSKEY{
		uint16(v0),
		byte(v1),
		byte(v2),
		key,
	}, nil
}

func mustParseDNSKEY(s string) DNSKEY {
	dnskey, _ := newDNSKEY(strings.SplitN(s, " ", 4))
	return *dnskey
}

func (dnskey DNSKEY) MarshalBinary(msg []byte) (data []byte, err error) {
	data = make([]byte, 4+len(dnskey.Key))
	binary.BigEndian.PutUint16(data, dnskey.Flags)
	data[2] = dnskey.Proto
	data[3] = dnskey.Algo
	copy(data[4:], dnskey.Key)
	return
}

func (dnskey DNSKEY) String() string {
	return fmt.Sprintf("%v %v %v %v", dnskey.Flags, dnskey.Proto, dnskey.Algo, base64.StdEncoding.EncodeToString(dnskey.Key))
}

func (dnskey DNSKEY) Digest(name string) ([]byte, error) {
	namebytes, err := encodeName(name, nil)
	if err != nil {
		return nil, err
	}
	dnskeybytes, err := dnskey.MarshalBinary(nil)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(append(namebytes, dnskeybytes...))
	return sum[:], nil
}
