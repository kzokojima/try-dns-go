package dns

import (
	"fmt"
	"testing"
)

func TestDNSKeyDigest(t *testing.T) {
	// root KSK
	{
		dnskey, err := newDNSKEY(
			[]string{"257", "3", "8", "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU="})
		if err != nil {
			t.FailNow()
		}
		sum, err := dnskey.Digest(".")
		if err != nil {
			t.FailNow()
		}
		if fmt.Sprintf("%X", sum) != "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D" {
			t.FailNow()
		}
	}

	// com KSK
	{
		dnskey, err := newDNSKEY(
			[]string{"257", "3", "8", "AQPDzldNmMvZFX4NcNJ0uEnKDg7tmv/F3MyQR0lpBmVcNcsIszxNFxsBfKNW9JYCYqpik8366LE7VbIcNRzfp2h9OO8HRl+H+E08zauK8k7evWEmu/6od+2boggPoiEfGNyvNPaSI7FOIroDsnw/taggzHRX1Z7SOiOiPWPNIwSUyWOZ79VmcQ1GLkC6NlYvG3HwYmynQv6oFwGv/KELSw7ZSdrbTQ0HXvZbqMUI7BaMskmvgm1G7oKZ1YiF7O9ioVNc0+7ASbqmZN7Z98EGU/Qh2K/BgUe8Hs0XVcdPKrtyYnoQHd2ynKPcMMlTEih2/2HDHjRPJ2aywIpKNnv4oPo/"})
		if err != nil {
			t.FailNow()
		}
		sum, err := dnskey.Digest("com.")
		if err != nil {
			t.FailNow()
		}
		if fmt.Sprintf("%X", sum) != "E2D3C916F6DEEAC73294E8268FB5885044A833FC5459588F4A9184CFC41A5766" {
			t.FailNow()
		}
	}
}
