package registrar

// maxCEVersion bounds the CEVersion a request may carry.
const maxCEVersion = 32

// validCEVersion reports whether v is a CEVersion the registrar keeps: 1 to
// 32 of A-Z, a-z, 0-9, '.', '_', '+' and '-'. The value comes from the
// requester and is shown to the approver, so anything else (spaces, other
// punctuation, text that could pass for another line of the page) is
// dropped.
func validCEVersion(v string) bool {
	if len(v) == 0 || len(v) > maxCEVersion {
		return false
	}
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c >= '0' && c <= '9', c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z',
			c == '.', c == '_', c == '+', c == '-':
		default:
			return false
		}
	}
	return true
}
