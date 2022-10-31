package dns

import "testing"

func TestRecursiveResolve(t *testing.T) {
	rrs, err := RecursiveResolve("one.one.one.one.", "A", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rrs[0].RData.String() != "1.1.1.1" && rrs[0].RData.String() != "1.0.0.1" {
		t.Fatal(rrs[0].RData.String())
	}
}
