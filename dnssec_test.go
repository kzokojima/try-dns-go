package dns

import (
	"strings"
	"testing"
)

func TestVerifySignature(t *testing.T) {
	var err error
	var b []byte
	var message []byte

	//
	// verify signature of DNSKEY RR
	//
	// root RRSIG of DNSKEY
	rrsig, err := newRRSIG(strings.Split("DNSKEY 8 0 172800 20221211000000 20221120000000 20326 . Y8Or1olHbjYMKfZxcKA8mP9+GWhl66Cu6Mrjh9NzLuBZ+14JZodwSJ5JaXzJxRzgHxTd/TWvnI4bAM/DQ8NYyRX/QezQdGU4ZE5RcrZLanxuX/FQR/qIMlLttCsoPtlM677HA3CecqLljbrcayIDSKMghh5iKV1iOoW1BP1KZwgH4Y87fiWbevk+AmN5xbJCPk1iCis+kMulacxTFC+g0jyLv1V0C2hneqZ58os/QvW7XNBWLd9OC1LbMVVkfgUsVYqfwLjcieQ5YVRshfy2Iazv2sLo87sGvBnLmSUx8F4hiotEK6UjTNNun1tKe0VTBVkXQyaIzfUOkPgoMoWojg==", " "))
	if err != nil {
		t.Fatal(err)
	}
	b, err = rrsig.MarshalBinaryWithoutSig()
	if err != nil {
		t.Fatal(err)
	}
	message = append(message, b...)

	// root ZSK
	zskDNSKey, err := newDNSKEY(strings.Split("256 3 8 AwEAAeB54o2xvW6vY4qQZ0krDsEZCe6MsRWCqsXd4+cNJZMePnlV/xwDrIbbeH1SJzv742rOHzgAKM1/3SQHHSkoEIPx8XQdHAZBxfhaXl3e8c5WrE3aGXS5AeTWAkt85ccqWgKyitxjFmJEOol0BqS2xueltaDwgWcC10nPUY+y5l/kTOYyptYQS4gg1uJNXIob/R1XIEJ10ZCurkYqZxgqyHc7tZv09N23o9rnGdjnYiArH7FjlXD8Rvjde8YWkmfdbCEWnchrnxDK8KV2/ZvBpG/WYnRKXYPUceGCw59OJdJ5M7utkm547RB3eEd8CVVhbXopZlsKq3GCrBwaIVe9ci0=", " "))
	if err != nil {
		t.Fatal(err)
	}
	zskRR := ResourceRecord{
		".",
		TypeDNSKEY,
		ClassIN,
		172800,
		zskDNSKey,
	}
	b, err = zskRR.Bytes(nil)
	if err != nil {
		t.Fatal(err)
	}
	message = append(message, b...)

	// root KSK
	kskDNSKey, err := newDNSKEY(strings.Split("257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=", " "))
	if err != nil {
		t.Fatal(err)
	}
	kskRR := ResourceRecord{
		".",
		TypeDNSKEY,
		ClassIN,
		172800,
		kskDNSKey,
	}
	b, err = kskRR.Bytes(nil)
	if err != nil {
		t.Fatal(err)
	}
	message = append(message, b...)

	err = verifySignature(message, kskDNSKey.Key, rrsig.Signature)
	if err != nil {
		t.Fatal(err)
	}

	//
	// verify signature of SOA RR
	//
	message = nil
	// root RRSIG of SOA
	rrsig, err = newRRSIG(strings.Split("SOA 8 0 86400 20221206050000 20221123040000 18733 . ieJensee3piTLdSd1AhvQYVjMsD8kHfosBeoNOUXC+jngk5jWWqOH/WNqE8pHtzEaEBzVXVrW1GxZZdc6GTmxQqZ49kKDZnuGVY1/8wGKq8AtiSrAJ/rr9YUb4zrwVjnnVlDDlMr7kCUUrH5K3C4CheMSjvljqcRAphMx8R4qSB+ZtFwz1H+loN7qzvztFZTAfcNAJQrTvoz+PduT7pvKWU7cwgu1foFSfLWvTJ3ZJYF2OAiLm7VG1IBBHsYXC0qXa3ropoaAfuHBbwYXt7Pf7UK7UwxmQkA1xUrI+csHMtF0SBmSUhwA6m2es54EPmQk8vf/1AGFg+1u9ReS68JVA==", " "))
	if err != nil {
		t.Fatal(err)
	}
	b, err = rrsig.MarshalBinaryWithoutSig()
	if err != nil {
		t.Fatal(err)
	}
	message = append(message, b...)
	// root SOA
	soa, err := newSOA(strings.Split("a.root-servers.net. nstld.verisign-grs.com. 2022112300 1800 900 604800 86400", " "))
	if err != nil {
		t.Fatal(err)
	}
	soaRR := ResourceRecord{
		".",
		TypeSOA,
		ClassIN,
		86400,
		soa,
	}
	b, err = soaRR.Bytes(nil)
	if err != nil {
		t.Fatal(err)
	}
	message = append(message, b...)
	err = verifySignature(message, zskDNSKey.Key, rrsig.Signature)
	if err != nil {
		t.Fatal(err)
	}
}
