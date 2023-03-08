package dns

import (
	"fmt"
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

	err = verifySignature(kskDNSKey.Key, message, rrsig.Signature)
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
	err = verifySignature(zskDNSKey.Key, message, rrsig.Signature)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGetRootAnchorDS(t *testing.T) {
	ds, err := getRootAnchorDS("root_files/root-anchors.xml")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%X", ds.digest) != "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D" {
		t.Fatalf("actual: %X", ds.digest)
	}
}

func TestVerifyRRSet(t *testing.T) {
	client := &BasicClient{Limit: 20}
	rootServer := "198.41.0.4"
	rootDS, err := getRootAnchorDS("root_files/root-anchors.xml")
	if err != nil {
		t.Fatal(err)
	}
	dnssecDSs := []DS{*rootDS}
	name := Name("com.")
	question := Question{name, TypeNS, ClassIN}
	res, err := client.Do("udp", rootServer+":53", question, false, true, true)
	if err != nil {
		t.Fatal(err)
	}
	authorityRRSets := NewRRSets(res.AuthorityResourceRecords)
	dsRRSet := authorityRRSets[Question{name, TypeDS, ClassIN}]
	rrsigRRSet := authorityRRSets[Question{name, TypeRRSIG, ClassIN}]
	zsk, err := getZSK(name.parent(), rootServer, dnssecDSs, client)
	if err != nil {
		t.Fatal(err)
	}
	err = verifyRRSet(zsk, dsRRSet, rrsigRRSet.RDatas[0].(RRSIG))
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRRSet2(t *testing.T) {
	var (
		err   error
		rrSet RRSet
		rrsig RRSIG
	)

	// verify DNSKEY RRSet of "com."
	zskDNSKey := mustParseDNSKEY("256 3 8 AwEAAbU0/L1XBGooCMnlQi1/60VALOD25bfj6WTnjwilw58VvOvo6+kP xQ+p0zv3ZR0lIIGf4P5lmfdF9RFBPTNBB3xMst3xkkww7Oy19t+q8kIX gtmtD7iTsZoXewNkBUc7FY5Gt+IuBc4Ouwj20U6WVjAs2/2NIrkxwpb9 /TJZzxoMCPkHue8bnDEjKwT626SpCE/drXm81wpceQjHzn0Imrs=")
	kskDNSKey := mustParseDNSKEY("257 3 8 AQPDzldNmMvZFX4NcNJ0uEnKDg7tmv/F3MyQR0lpBmVcNcsIszxNFxsB fKNW9JYCYqpik8366LE7VbIcNRzfp2h9OO8HRl+H+E08zauK8k7evWEm u/6od+2boggPoiEfGNyvNPaSI7FOIroDsnw/taggzHRX1Z7SOiOiPWPN IwSUyWOZ79VmcQ1GLkC6NlYvG3HwYmynQv6oFwGv/KELSw7ZSdrbTQ0H XvZbqMUI7BaMskmvgm1G7oKZ1YiF7O9ioVNc0+7ASbqmZN7Z98EGU/Qh 2K/BgUe8Hs0XVcdPKrtyYnoQHd2ynKPcMMlTEih2/2HDHjRPJ2aywIpK Nnv4oPo/")
	rrSet = RRSet{"com.", TypeDNSKEY, ClassIN, 86400, []RData{zskDNSKey, kskDNSKey}}
	rrsig = mustParseRRSIG("DNSKEY 8 1 86400 20221216182421 20221201181921 30909 com. Tb327kPhjTTD9JPdRAfYdsQMKU6wh23hz1WMFBmt+YjmsnNsqUFM1JzB wJ99by2MCvDrf8lszPS/zOflUf8xuIyQL0iydFLK5LpTTNcjfcvDvxzU R1dLKrwS0Bg4+vmJeZ+zAfO8DFVAIGzHvn8eTNbZsOgiAjkzViNZd5P6 5DXVRchKA3vH7oFwiV77zUJMSxLOQiSEAplPAeFZA3ujoA0zNupKnhUh F9WmxHwXA7wZgE1YwxDR8cuprY9yLxKMDDHWG+Fzt7WmfFQhDoLYPdx4 3c+cbXyAvQvM5Yln3lCUKDpjJRk6OHZqLL4aP7ks0v9H6ITCyV/WvH02 inkX+A==")
	err = verifyRRSet(kskDNSKey.Key, &rrSet, rrsig)
	if err != nil {
		t.Fatal(err)
	}

	// verify DS RRSet of "verisign.com."
	rrSet = RRSet{"verisign.com.", TypeDS, ClassIN, 86400, []RData{
		mustParseDS("55204 8 2 206D88653C43D99BF4567BBD7DF9C078DB357F59AA183741024D3457 23052E88"),
	}}
	rrsig = mustParseRRSIG("DS 8 2 86400 20221216051736 20221209040736 53929 com. ZJVa2+Vqd2wWbVwf6a16nf8Z00MmpGQDEGqgbOSt/HSfjh4ZsgbwBTaU 8j2XASY9RAqd4Xnam+mdGUqigx1OE+4JfczbM5zJbdrd9J1ge9FKbQ3V g4Zsml9QUUrH6s8HjmfGytIw1GNa6xUJnM9irnmqbloeAGq94vVxdPYs 6ecBe1fmcwMjq5p38RWwO1RDlVzvMIwPmhesKmoQ+YHgxw==")
	err = verifyRRSet(zskDNSKey.Key, &rrSet, rrsig)
	if err != nil {
		t.Fatal(err)
	}

	// verify DS RRSet of "example.com."
	rrSet = RRSet{"example.com.", TypeDS, ClassIN, 86400, []RData{
		mustParseDS("31589 8 1 3490A6806D47F17A34C29E2CE80E8A999FFBE4BE"),
		mustParseDS("31589 8 2 CDE0D742D6998AA554A92D890F8184C698CFAC8A26FA59875A990C03 E576343C"),
		mustParseDS("43547 8 1 B6225AB2CC613E0DCA7962BDC2342EA4F1B56083"),
		mustParseDS("43547 8 2 615A64233543F66F44D68933625B17497C89A70E858ED76A2145997E DF96A918"),
		mustParseDS("31406 8 1 189968811E6EBA862DD6C209F75623D8D9ED9142"),
		mustParseDS("31406 8 2 F78CF3344F72137235098ECBBD08947C2C9001C7F6A085A17F518B5D 8F6B916D"),
	}}
	rrsig = mustParseRRSIG("DS 8 2 86400 20221212051553 20221205040553 53929 com. JjgTzM/cAorgscQOn4211xbU17GrwIzcab0qTEscZuREUoTYs0iUv3oe j6OnEsDpSicqiLJ0ZL96XhRXiIFCeuq0IVRBn0k/PcOusmya+GLrNxUt +d0lWpc28ZAmyW7NKy7jifk5hYjBaM+TT6RUmjuh/Tvqw1vujrTAZg7b JwxQgcWWaRhztkRBFBPpbdZ+UDesiEo6buDi4WqYN5rR9w==")
	err = verifyRRSet(zskDNSKey.Key, &rrSet, rrsig)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRRSet3(t *testing.T) {
	var (
		err   error
		rrSet RRSet
		rrsig RRSIG
	)

	// verify DNSKEY RRSet of "example.com."
	zskDNSKey := mustParseDNSKEY("256 3 8 AwEAAb1oJO+fCqdkxHtQYVB/tFPgJphc+VxjUYz+eVGf077zMxHKgce9 EwGBifFuKhjl2EA0VQPsWVX1vzuUmWri3OgsTBlITkdMz6VU4g94uO6T 9MIktokouOidIzvOqLR+O2LSXNhiYOIWA9s3Lxk5R2lrwd6vrRvT2CR1 GdZuUlKB")
	kskDNSKey1 := mustParseDNSKEY("257 3 8 AwEAAZ0aqu1rJ6orJynrRfNpPmayJZoAx9Ic2/Rl9VQWLMHyjxxem3VU SoNUIFXERQbj0A9Ogp0zDM9YIccKLRd6LmWiDCt7UJQxVdD+heb5Ec4q lqGmyX9MDabkvX2NvMwsUecbYBq8oXeTT9LRmCUt9KUt/WOi6DKECxoG /bWTykrXyBR8elD+SQY43OAVjlWrVltHxgp4/rhBCvRbmdflunaPIgu2 7eE2U4myDSLT8a4A0rB5uHG4PkOa9dIRs9y00M2mWf4lyPee7vi5few2 dbayHXmieGcaAHrx76NGAABeY393xjlmDNcUkF1gpNWUla4fWZbbaYQz A93mLdrng+M=")
	kskDNSKey2 := mustParseDNSKEY("257 3 8 AwEAAbOFAxl+Lkt0UMglZizKEC1AxUu8zlj65KYatR5wBWMrh18TYzK/ ig6Y1t5YTWCO68bynorpNu9fqNFALX7bVl9/gybA0v0EhF+dgXmoUfRX 7ksMGgBvtfa2/Y9a3klXNLqkTszIQ4PEMVCjtryl19Be9/PkFeC9ITjg MRQsQhmB39eyMYnal+f3bUxKk4fq7cuEU0dbRpue4H/N6jPucXWOwiMA kTJhghqgy+o9FfIp+tR/emKao94/wpVXDcPf5B18j7xz2SvTTxiuqCzC MtsxnikZHcoh1j4g+Y1B8zIMIvrEM+pZGhh/Yuf4RwCBgaYCi9hpiMWV vS4WBzx0/lU=")
	rrSet = RRSet{"example.com.", TypeDNSKEY, ClassIN, 3600, []RData{
		zskDNSKey,
		kskDNSKey1,
		kskDNSKey2,
	}}
	rrsig = mustParseRRSIG("DNSKEY 8 2 3600 20221214114359 20221123003333 45620 example.com. PFCEgkqMr3VlJFNYnbziXFFDhn22aXd6E7enITfzETgfgLRwjwxhxpOZ u/vzcVgGYFNsAsBShdmsEq6pOJsTeL2GhDwyM0hSNPO6ITP27oua94yu u/vlJU5N4ff6O1WVibQTMSTjonUbBV0z96CbOuzZX+cn1O7kEoRur/dN nwbXAS/5YXllu/EEn8R2F0TNYaYXTza/juKRCtDsHBIztVR7aBiIqEdl KVYu5TCLJiBKqsIXNo1K/1S2GcQ2CrnG92sLwFVBA44eoboNn7DLVrLV z3MN55Roquyjk7XAvaPA+XUHY78GhmMvYzlVEZfaBDNH/hXlp71yL7gJ SG3ikg==")
	err = verifyRRSet(kskDNSKey1.Key, &rrSet, rrsig)
	if err != nil {
		t.Fatal(err)
	}
	rrsig = mustParseRRSIG("DNSKEY 8 2 3600 20221214114359 20221123003333 31406 example.com. ZwIicJftiyxxBKr7Y3PNvO0BbxXosRXUjnbKe4f9SjtnwppHpC22aKsh jr2zvkEDD89q7XPs98hQuxtUw2Ra/lRARucuWAdGX4hp41/LMRkzdBaS GuLNbIXPB4pQWfF6ErO+XvhLknWXrj4WDHpjnS5drMT2sAP77M8zf5kP huUpMj6AYqOwWPR/JUjgE8YPU3zLdskpRjF4JCDZ8J2cqABNRMHPbnss bli8qDkKgT2yGJbBsnhHkdFWpaFLHbfn0SOLuFoLtImIITOeK8xC0qPY 5u+1eitpMt7WoKPYfOgHPrPkHRgI2HjSFOXNybmhIcJ2mwZ76BIKpX9b GgEAoA==")
	err = verifyRRSet(kskDNSKey2.Key, &rrSet, rrsig)
	if err != nil {
		t.Fatal(err)
	}

	// verify A RRSet of "example.com."
	rrSet = RRSet{"example.com.", TypeA, ClassIN, 86400, []RData{
		mustParseA("93.184.216.34"),
	}}
	rrsig = mustParseRRSIG("A 8 2 86400 20221220080923 20221129053336 59208 example.com. H6tWP087fHsTBz2/IimDLUH8xJYr+SRnkPLNDQ61kNCgzDYOMPzenVmU dPmhkTRu3zUyThJCTs8UwVzXGuwh5tmerMKt9Q36PaiXr2FyHi9I6vgS iSP0TZttSBbcDopJb9hzSHWt7hoGHxNEnrU21qpw5OpTO8JOiXSbYMS0 kGY=")
	err = verifyRRSet(zskDNSKey.Key, &rrSet, rrsig)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRRSet4(t *testing.T) {
	var (
		err   error
		rrSet RRSet
		rrsig RRSIG
	)

	// verify DNSKEY RRSet of "jp."
	zskDNSKey1 := mustParseDNSKEY("256 3 8 AwEAAbCAyAkjQggI2xUJnT5vWwGbk2IqqyXmkHJlJefJtw4WUHSiLfS+ AXTjdovpoJ6xueDJFZi0s7Oycjv1zzDbW7J6YjKpwgY/LaG1U7DZ7ob9 HySBkxzXMNZMT/2VmDBCA0g3IA0/zWXhS/m4Os0d/WfsieojTmvzY8m2 quHbfcC1")
	zskDNSKey2 := mustParseDNSKEY("256 3 8 AwEAAb3DEkGKOwCqNkTSssmGwgyFaMUj33wyr2mM0v0ZhIAWHIJMjzcB ri7qOHn36nrMZfAt/W54TAhrlvLISqIC3B/MJmfdHVqMnt6I9LmybNGA jKz770j6NnSJfJ8qs7PJ8ngWeiiiQ1QB883D6uJgmaGo6XZAcC9nTJn/ TDXd0KYp")
	kskDNSKey := mustParseDNSKEY("257 3 8 AwEAAZaf5AuDt8JeoIjFPmAhgyfnWz91O4BZtbdmWoD0m7WqiD2qr2GO DxyYLWupRKiunPQ15GFUf3uMCpscYBL+CjN0DLyr6/EEOQ40sWOzEvAx T19e4S0vvfNxrRzfz85RpbuBjZrENH8PdT0n2VE1ySlmDhlEGrqy9A4M wn5IydZwkHHl/TK8/OMrS2V3HpVintdAl+UWoSBDMGNugHyPZEHYsFSG bpnFg6bqfrq6yjfQxxWtFmrXn1S1FKhf5gxfidWGtBmtuK9TxGUkN0xi kMzdsa9m0AjJEsxPjrwotxgyT8QRQV2cJvzmad89T28IDKgETo+St6+i Oo/+PM91Ekc=")
	rrSet = RRSet{"jp.", TypeDNSKEY, ClassIN, 86400, []RData{
		zskDNSKey1,
		zskDNSKey2,
		kskDNSKey,
	}}
	rrsig = mustParseRRSIG("DNSKEY 8 1 86400 20230202184500 20221203184500 39916 jp. Jh7xOC2/XGfw/B/KiqEiO6oCsT8lRvo3bMiYdvJ2/7OvRL/1ezMaix5V fpGo55nuWeTNs6Mim5MdJm+nkUh7q3DnaXLPPIYCTAKZ8k85J2w7m2kc nZoEQ9enqIXrUz9GiC6QwKqDePhab4hziXx99cKVgwB0GQPehKh5iEcC PteibbiWrVEmkS0bDUG42TrmqsyPzjX1s+c5CMpbc2PCzYpW6aMX6EVR FBf4HGdUxgO4RGJ8uGUnw/XJn6tjs44e7ow8RjbBQS/EwICmAgrYQm4q lFoeZjouUQpNVQiB6eV1cIJ4PDKz6tI6U8sl1qmKESgq/2+YpP1D7g/P V31iug==")
	err = verifyRRSet(kskDNSKey.Key, &rrSet, rrsig)
	if err != nil {
		t.Fatal(err)
	}

	// verify DS RRSet of "jprs.jp."
	rrSet = RRSet{"jprs.jp.", TypeDS, ClassIN, 7200, []RData{
		mustParseDS("6856 8 2 4D06600DDB3967F38997FA74706624E3DB15159464A4F0E4C27F7DAB C8E0E7A6"),
	}}
	rrsig = mustParseRRSIG("DS 8 2 7200 20230102174503 20221203174503 17286 jp. YFzNuU5yViHpaidYKmwtMY/3cnKdxeNPHbp6HLV/pYoakVT+MGOuVibY EICIzPxPILyH9bfesw5Zf65Sdef7Au5sAdid2hlXFonDyqtU3bwceuJr PlBO8Ykdd6N7K8fyMwkpAtN9vpAZJ5KiT93Ut9eJfUt6kkUZv4C/fME3 cog=")
	err = verifyRRSet(zskDNSKey1.Key, &rrSet, rrsig)
	if err != nil {
		t.Fatal(err)
	}
}
