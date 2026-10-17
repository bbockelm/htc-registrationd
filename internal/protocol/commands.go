// Package protocol defines the htc-registrationd CEDAR surface: command
// numbers, the attribute names of the request and reply ClassAds, and typed
// encode/decode helpers shared by the registrar, the CE daemon and the CLI.
package protocol

// Command numbers. They are defined here, as golang-htcondor's placementd
// client does for its commands, rather than in condor_commands.h.
//
// The block 77000-77099 is unused in condor_commands.h: the DaemonCore-style
// bases there are DC_BASE 60000, FILETRANSFER_BASE 61000, DAGMAN_BASE 61500,
// PW_BASE 70000 (commented out), DCSHADOW_BASE 71000, SQUAWK 72000,
// DCGRIDMANAGER_BASE 73000, the transfer daemon's base 74000 (commented out,
// reused by htcondordb) and CREDD_BASE 81000. cedar's commands package also names a
// CREDD_BASE of 75000, so 75000 is avoided too. Re-check against
// condor_commands.h before tagging a release.
const (
	// Base is the first command number of the block.
	Base = 77000

	// Served by the registrar.

	// RegRequest starts a registration (callback or approval). ALLOW +
	// encryption; the client verifies the registrar's server certificate.
	RegRequest = Base + 0
	// RegPoll polls an approval-mode request. ALLOW + encryption.
	RegPoll = Base + 1
	// RegRenew renews an approval-mode registration with a refresh secret.
	// ALLOW + encryption.
	RegRenew = Base + 2

	// Served by the CE.

	// RegCallback is the registrar's callback to a CE in callback mode. ALLOW
	// + encryption; the CE authenticates with its SSL host certificate.
	RegCallback = Base + 3
	// RegStatus reports the CE daemon's registration state. READ.
	RegStatus = Base + 4
	// RegRenewNow asks the CE daemon to renew immediately. ADMINISTRATOR.
	RegRenewNow = Base + 5
	// RegRequestApproval asks the CE daemon to start an approval-mode
	// request now and replies with its URL and code. ADMINISTRATOR.
	RegRequestApproval = Base + 6

	// Registrar administration (CLI path). ADMINISTRATOR.

	// RegAdminList lists requests and registrations.
	RegAdminList = Base + 10
	// RegAdminApprove approves a pending approval-mode request.
	RegAdminApprove = Base + 11
	// RegAdminDeny denies a pending approval-mode request.
	RegAdminDeny = Base + 12
	// RegAdminRevoke revokes a registration.
	RegAdminRevoke = Base + 13
)

// CommandName returns a human-readable name for a registration command, or ""
// for a number outside the block.
func CommandName(cmd int) string {
	switch cmd {
	case RegRequest:
		return "REG_REQUEST"
	case RegPoll:
		return "REG_POLL"
	case RegRenew:
		return "REG_RENEW"
	case RegCallback:
		return "REG_CALLBACK"
	case RegStatus:
		return "REG_STATUS"
	case RegRenewNow:
		return "REG_RENEW_NOW"
	case RegRequestApproval:
		return "REG_REQUEST_APPROVAL"
	case RegAdminList:
		return "REG_ADMIN_LIST"
	case RegAdminApprove:
		return "REG_ADMIN_APPROVE"
	case RegAdminDeny:
		return "REG_ADMIN_DENY"
	case RegAdminRevoke:
		return "REG_ADMIN_REVOKE"
	}
	return ""
}

// EncryptedCommands are the commands that negotiate SSL only, with
// encryption required, and whose handlers refuse an unencrypted session. They
// carry nonces, request ids, refresh secrets or tokens.
var EncryptedCommands = []int{RegRequest, RegPoll, RegRenew, RegCallback}

// AdminCommands are the registrar's administration commands. They
// authenticate by any method the ADMINISTRATOR level allows, but require
// encryption, and their handlers refuse an unencrypted session: they carry
// user codes, decisions and the registration list.
var AdminCommands = []int{RegAdminList, RegAdminApprove, RegAdminDeny, RegAdminRevoke}
