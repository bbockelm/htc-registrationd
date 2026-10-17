package protocol

import (
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	in := PollReply{
		Status:   StatusApproved,
		Interval: 5,
		Grant:    Grant{RegistrationID: "r1", Token: "a.b.c", Expiry: 1800000000, RefreshSecret: "s"},
		Error:    Error{Code: 0, Message: ""},
	}
	ad := Encode(&in)
	if _, ok := ad.Lookup(AttrErrorCode); ok {
		t.Error("zero ErrorCode was encoded")
	}
	var out PollReply
	if err := Decode(ad, &out); err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("round trip: %+v != %+v", out, in)
	}
	if out.AsError() != nil {
		t.Fatal("no error expected")
	}
}

func TestDecodeErrorAndTypes(t *testing.T) {
	ad := Encode(&Ack{Status: StatusError, Error: *Err(ErrRevoked, "gone %d", 1)})
	var r RenewReply
	if err := Decode(ad, &r); err != nil {
		t.Fatal(err)
	}
	if r.Code != ErrRevoked || r.Message != "gone 1" || r.AsError() == nil {
		t.Fatalf("decoded %+v", r)
	}
	bad := classad.New()
	_ = bad.Set(AttrStatus, int64(3))
	if err := Decode(bad, &r); err == nil {
		t.Fatal("an integer Status decoded into a string")
	}
	if err := Decode(bad, r); err == nil {
		t.Fatal("a non-pointer decoded")
	}
}

func TestCommandBlock(t *testing.T) {
	seen := map[int]bool{}
	for _, c := range []int{RegRequest, RegPoll, RegRenew, RegCallback, RegStatus, RegRenewNow,
		RegAdminList, RegAdminApprove, RegAdminDeny, RegAdminRevoke} {
		if c < 77000 || c > 77099 || seen[c] || CommandName(c) == "" {
			t.Errorf("command %d out of block, duplicated or unnamed", c)
		}
		seen[c] = true
	}
}
