package protocol

import (
	"fmt"
	"reflect"

	"github.com/PelicanPlatform/classad/classad"
)

// Methods a CE can request a registration with.
const (
	MethodCallback = "callback"
	MethodApproval = "approval"
)

// Status values carried in the Status attribute of replies.
const (
	StatusOK              = "ok"
	StatusError           = "error"
	StatusCallbackPending = "callback-pending" // REG_REQUEST callback: first reply
	StatusIssued          = "issued"           // REG_REQUEST callback: second reply, token delivered
	StatusFailed          = "failed"           // REG_REQUEST callback: second reply, no token
	StatusPending         = "pending"          // approval request awaiting a decision
	StatusSlowDown        = "slow-down"        // poll arrived too early; honour the new Interval
	StatusApproved        = "approved"
	StatusDenied          = "denied"
	StatusExpired         = "expired"
	StatusClaimed         = "claimed" // approved request whose first secret was already proven
	StatusRevoked         = "revoked"
)

// Error codes carried in ErrorCode. ErrorString always explains.
const (
	ErrNotEncrypted   = 1  // the session is not encrypted
	ErrBadRequest     = 2  // malformed or missing attributes
	ErrRateLimited    = 3  // pending caps or per-name back-off
	ErrNameRefused    = 4  // the name policy refused the name
	ErrCallbackDenied = 5  // the callback address failed the SSRF policy
	ErrCallbackFailed = 6  // the callback could not be completed
	ErrUnknown        = 7  // unknown request, registration or secret
	ErrRevoked        = 8  // the registration is revoked
	ErrInternal       = 9  // registrar-side failure (database, signing key)
	ErrNotAuthorized  = 10 // the approver is no longer authorized
	ErrExpired        = 11 // the request or registration expired
	ErrNotFound       = 12 // admin command target not found
)

// Attribute names.
const (
	AttrStatus                  = "Status"
	AttrErrorCode               = "ErrorCode"
	AttrErrorString             = "ErrorString"
	AttrName                    = "Name"
	AttrMethod                  = "Method"
	AttrCallbackAddress         = "CallbackAddress"
	AttrNonce                   = "Nonce"
	AttrCEVersion               = "CEVersion"
	AttrRequestID               = "RequestId"
	AttrUserCode                = "UserCode"
	AttrVerificationURI         = "VerificationURI"
	AttrVerificationURIComplete = "VerificationURIComplete"
	AttrInterval                = "Interval"
	AttrExpiresIn               = "ExpiresIn"
	AttrRegistrationID          = "RegistrationId"
	AttrToken                   = "Token"
	AttrExpiry                  = "Expiry"
	AttrRefreshSecret           = "RefreshSecret"
	AttrRequestNumber           = "RequestNumber"
	AttrReason                  = "Reason"
	AttrHint                    = "Hint"
	AttrEnd                     = "RegListEnd"
)

// Error is the error part of a reply.
type Error struct {
	Code    int64  `ad:"ErrorCode"`
	Message string `ad:"ErrorString"`
}

// Err builds an *Error.
func Err(code int, format string, args ...any) *Error {
	return &Error{Code: int64(code), Message: fmt.Sprintf(format, args...)}
}

func (e *Error) Error() string { return fmt.Sprintf("registration error %d: %s", e.Code, e.Message) }

// Request is REG_REQUEST's request ad (CE → registrar).
type Request struct {
	Name            string `ad:"Name"`
	Method          string `ad:"Method"`
	CallbackAddress string `ad:"CallbackAddress"`
	Nonce           string `ad:"Nonce"`
	CEVersion       string `ad:"CEVersion"`
}

// RequestReply is REG_REQUEST's first reply. In callback mode a second reply,
// a CallbackOutcome, follows on the same connection once the callback has run.
// The token is never sent on this connection.
type RequestReply struct {
	Status                  string `ad:"Status"`
	RequestID               string `ad:"RequestId"`
	UserCode                string `ad:"UserCode"`
	VerificationURI         string `ad:"VerificationURI"`
	VerificationURIComplete string `ad:"VerificationURIComplete"`
	Interval                int64  `ad:"Interval"`
	ExpiresIn               int64  `ad:"ExpiresIn"`
	Error
}

// CallbackOutcome is REG_REQUEST's second reply in callback mode.
type CallbackOutcome struct {
	Status string `ad:"Status"` // StatusIssued or StatusFailed
	Error
}

// Poll is REG_POLL's request ad.
type Poll struct {
	RequestID string `ad:"RequestId"`
	Nonce     string `ad:"Nonce"`
}

// Grant is the token and secret material an approval-mode reply carries.
type Grant struct {
	RegistrationID string `ad:"RegistrationId"`
	Token          string `ad:"Token"`
	Expiry         int64  `ad:"Expiry"`
	RefreshSecret  string `ad:"RefreshSecret"`
}

// PollReply is REG_POLL's reply.
type PollReply struct {
	Status   string `ad:"Status"`
	Interval int64  `ad:"Interval"`
	Grant
	Error
}

// Renew is REG_RENEW's request ad.
type Renew struct {
	RegistrationID string `ad:"RegistrationId"`
	RefreshSecret  string `ad:"RefreshSecret"`
}

// RenewReply is REG_RENEW's reply. On success RefreshSecret is the new pending
// secret.
type RenewReply struct {
	Status string `ad:"Status"`
	Grant
	Error
}

// CallbackHello opens REG_CALLBACK (registrar → CE).
type CallbackHello struct {
	RequestID string `ad:"RequestId"`
}

// CallbackProof is the CE's answer to CallbackHello: the request's Nonce.
type CallbackProof struct {
	Status string `ad:"Status"`
	Nonce  string `ad:"Nonce"`
	Error
}

// CallbackDelivery carries the token to the CE (registrar → CE).
type CallbackDelivery struct {
	Name   string `ad:"Name"`
	Token  string `ad:"Token"`
	Expiry int64  `ad:"Expiry"`
}

// Ack is a bare status reply.
type Ack struct {
	Status string `ad:"Status"`
	Hint   string `ad:"Hint"`
	Error
}

// AdminTarget names what an admin command acts on. Approve and deny take a
// UserCode or RequestNumber; approve also takes the Name the request must
// carry, and Replace to approve a name that already has an active
// registration. Revoke takes a RegistrationId or a Name (all of that name's
// active registrations).
type AdminTarget struct {
	UserCode       string `ad:"UserCode"`
	RequestNumber  int64  `ad:"RequestNumber"`
	RegistrationID string `ad:"RegistrationId"`
	Name           string `ad:"Name"`
	Replace        bool   `ad:"Replace"`
	Reason         string `ad:"Reason"`
}

// Encode returns v (a pointer to, or value of, one of the message structs) as
// a ClassAd. Zero-valued fields are omitted, so absence and emptiness read the
// same on the far side.
func Encode(v any) *classad.ClassAd {
	ad := classad.New()
	encodeInto(ad, reflect.Indirect(reflect.ValueOf(v)))
	return ad
}

func encodeInto(ad *classad.ClassAd, rv reflect.Value) {
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		f, fv := rt.Field(i), rv.Field(i)
		if f.Anonymous && fv.Kind() == reflect.Struct {
			encodeInto(ad, fv)
			continue
		}
		name := f.Tag.Get("ad")
		if name == "" || fv.IsZero() {
			continue
		}
		switch fv.Kind() {
		case reflect.String:
			_ = ad.Set(name, fv.String())
		case reflect.Int64, reflect.Int:
			_ = ad.Set(name, fv.Int())
		case reflect.Bool:
			_ = ad.Set(name, fv.Bool())
		default:
			panic(fmt.Sprintf("protocol: unsupported field kind %s for %s", fv.Kind(), name))
		}
	}
}

// Decode fills v (a pointer to one of the message structs) from ad. Missing
// attributes leave fields zero; an attribute of the wrong type is an error.
func Decode(ad *classad.ClassAd, v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("protocol: Decode needs a pointer to a struct, got %T", v)
	}
	return decodeInto(ad, rv.Elem())
}

func decodeInto(ad *classad.ClassAd, rv reflect.Value) error {
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		f, fv := rt.Field(i), rv.Field(i)
		if f.Anonymous && fv.Kind() == reflect.Struct {
			if err := decodeInto(ad, fv); err != nil {
				return err
			}
			continue
		}
		name := f.Tag.Get("ad")
		if name == "" {
			continue
		}
		if _, ok := ad.Lookup(name); !ok {
			continue
		}
		switch fv.Kind() {
		case reflect.String:
			s, ok := ad.EvaluateAttrString(name)
			if !ok {
				return fmt.Errorf("protocol: attribute %s is not a string", name)
			}
			fv.SetString(s)
		case reflect.Int64, reflect.Int:
			n, ok := ad.EvaluateAttrInt(name)
			if !ok {
				return fmt.Errorf("protocol: attribute %s is not an integer", name)
			}
			fv.SetInt(n)
		case reflect.Bool:
			b, ok := ad.EvaluateAttrBool(name)
			if !ok {
				return fmt.Errorf("protocol: attribute %s is not a boolean", name)
			}
			fv.SetBool(b)
		default:
			return fmt.Errorf("protocol: unsupported field kind %s for %s", fv.Kind(), name)
		}
	}
	return nil
}

// AsError returns the reply's error, or nil when it carries none.
func (e Error) AsError() error {
	if e.Code == 0 && e.Message == "" {
		return nil
	}
	ee := e
	return &ee
}
