package secret

import "testing"

func TestSecrets(t *testing.T) {
	a, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewSecret()
	if len(a) != 43 || a == b {
		t.Fatalf("secrets %q %q", a, b)
	}
	if id, _ := NewID(); len(id) != 22 {
		t.Fatalf("id %q", id)
	}
	if !Matches(a, Hash(a)) || Matches(b, Hash(a)) || Matches(a, "") {
		t.Fatal("Matches")
	}
	if Equal("x", "xy") || !Equal("x", "x") {
		t.Fatal("Equal")
	}
}
