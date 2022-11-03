package dns

import "testing"

func TestResolve(t *testing.T) {
	rootServer = "198.41.0.4"
	rrs, err := Resolve(Question{Name("one.one.one.one."), TypeA, ClassIN}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rrs[0].RData.String() != "1.1.1.1" && rrs[0].RData.String() != "1.0.0.1" {
		t.Fatal(rrs[0].RData.String())
	}
}
