package dns

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"math/big"
	"os"
	"sort"
)

func verifySignature(pubkeyBytes []byte, message []byte, signature []byte) error {
	pub := decodePublicKey(pubkeyBytes)
	hashed := sha256.Sum256(message)
	return rsa.VerifyPKCS1v15(&pub, crypto.SHA256, hashed[:], signature)
}

func decodePublicKey(key []byte) rsa.PublicKey {
	// RFC 3110
	var exponentLen uint16
	var offset uint16
	if key[0] == 0 {
		exponentLen = binary.BigEndian.Uint16(key[1:])
		offset = 3
	} else {
		exponentLen = uint16(key[0])
		offset = 1
	}
	return rsa.PublicKey{
		N: new(big.Int).SetBytes(key[offset+exponentLen:]),
		E: int(new(big.Int).SetBytes(key[offset : offset+exponentLen]).Int64()),
	}
}

type TrustAnchor struct {
	Id         string      `xml:"id,attr"`
	Source     string      `xml:"source,attr"`
	Zone       string      `xml:"Zone"`
	KeyDigests []KeyDigest `xml:"KeyDigest"`
}

type Digest []byte

func (d *Digest) UnmarshalText(text []byte) error {
	b := make([]byte, len(text)/2)
	_, err := fmt.Sscanf(string(text), "%X", &b)
	if err != nil {
		return err
	}
	*d = b
	return nil
}

type KeyDigest struct {
	Id         string `xml:"id,attr"`
	ValidFrom  string `xml:"validFrom,attr"`
	ValidUntil string `xml:"validUntil,attr"`
	KeyTag     uint16 `xml:"KeyTag"`
	Algorithm  byte   `xml:"Algorithm"`
	DigestType byte   `xml:"DigestType"`
	Digest     Digest `xml:"Digest"`
}

func (kd *KeyDigest) toDS() DS {
	return DS{kd.KeyTag, kd.Algorithm, kd.DigestType, kd.Digest}
}

func readRootAnchorsXML(path string) (*TrustAnchor, error) {
	r, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var trustAnchor TrustAnchor
	err = xml.Unmarshal(b, &trustAnchor)
	if err != nil {
		return nil, err
	}
	return &trustAnchor, nil
}

func getRootAnchorDS(path string) (*DS, error) {
	trustAnchor, err := readRootAnchorsXML(path)
	if err != nil {
		return nil, err
	}
	ds := trustAnchor.KeyDigests[len(trustAnchor.KeyDigests)-1].toDS()
	return &ds, nil
}

func getZSK(name Name, nameServer string, dnssecDSs []DS, client Client) ([]byte, error) {
	question := Question{name, TypeDNSKEY, ClassIN}
	Log.Debugf("getZSK: send request: @%v %v", nameServer, question)
	res, err := client.Do("udp", nameServer+":53", question, false, true, true)
	if err != nil {
		return nil, err
	}
	answerRRSets := NewRRSets(res.AnswerResourceRecords)
	dnskeyRRSet, ok := answerRRSets[question]
	if !ok {
		return nil, fmt.Errorf("not found DNSKEY")
	}
	rrsigRRSet, ok := answerRRSets[Question{name, TypeRRSIG, ClassIN}]
	if !ok {
		return nil, fmt.Errorf("not found RRSIG of DNSKey")
	}

	var zskDNSKey, kskDNSKey RData
	for _, v := range dnskeyRRSet.RDatas {
		switch v.(DNSKEY).Flags {
		case 256:
			zskDNSKey = v.(DNSKEY)
		case 257:
			kskDNSKey = v.(DNSKEY)
		}
	}
	if zskDNSKey == nil || kskDNSKey == nil {
		return nil, fmt.Errorf("not found DNSKEY")
	}

	// vefiry KSK
	digest, err := kskDNSKey.(DNSKEY).Digest(name.String())
	if err != nil {
		return nil, err
	}
	for _, ds := range dnssecDSs {
		if bytes.Equal(digest, ds.digest) { // TODO
			goto VERIFY
		}
	}
	return nil, fmt.Errorf("error KSK")

VERIFY:

	// verify DNSKey
	for _, v := range rrsigRRSet.RDatas {
		err = verifyRRSet(kskDNSKey.(DNSKEY).Key, dnskeyRRSet, v.(RRSIG))
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, err
	}

	return zskDNSKey.(DNSKEY).Key, nil
}

func verifyRRSet(key []byte, rrSet *RRSet, rrsig RRSIG) error {
	message, err := rrsig.MarshalBinaryWithoutSig()
	if err != nil {
		return err
	}

	// sort rdatas
	var rdatas [][]byte
	for _, v := range rrSet.RDatas {
		b, err := v.MarshalBinary(nil)
		if err != nil {
			return err
		}
		rdatas = append(rdatas, b)
	}
	sort.Slice(rdatas, func(i, j int) bool { return bytes.Compare(rdatas[i], rdatas[j]) < 0 })

	// NAME + TYPE + CLASS + TTL + RDLENGTH
	encoded, err := encodeName(rrSet.Name.String(), nil)
	if err != nil {
		return err
	}
	l := len(encoded)
	first := make([]byte, l+10) // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
	copy(first, encoded)
	binary.BigEndian.PutUint16(first[l:], uint16(rrSet.Type))
	binary.BigEndian.PutUint16(first[l+2:], uint16(rrSet.Class))
	binary.BigEndian.PutUint32(first[l+4:], uint32(rrSet.TTL))

	for _, v := range rdatas {
		binary.BigEndian.PutUint16(first[l+8:], uint16(len(v)))
		message = append(message, first...)
		message = append(message, v...)
	}
	err = verifySignature(key, message, rrsig.Signature)
	if err != nil {
		return fmt.Errorf("failed verifyRRSet(key: %x, rrSet: %v, rrsig: %v) error: %w", key, rrSet, rrsig, err)
	}
	return nil
}
