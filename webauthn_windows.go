//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Bindings for the subset of webauthn.h (Windows 10 1903+) needed for
// WebAuthNAuthenticatorGetAssertion. Struct layouts must match the C headers.

var (
	modWebAuthn = windows.NewLazySystemDLL("webauthn.dll")
	modUser32   = windows.NewLazySystemDLL("user32.dll")
	modKernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procGetApiVersionNumber    = modWebAuthn.NewProc("WebAuthNGetApiVersionNumber")
	procGetAssertion           = modWebAuthn.NewProc("WebAuthNAuthenticatorGetAssertion")
	procFreeAssertion          = modWebAuthn.NewProc("WebAuthNFreeAssertion")
	procGetErrorName           = modWebAuthn.NewProc("WebAuthNGetErrorName")
	procGetCancellationId      = modWebAuthn.NewProc("WebAuthNGetCancellationId")
	procCancelCurrentOperation = modWebAuthn.NewProc("WebAuthNCancelCurrentOperation")

	procGetForegroundWindow = modUser32.NewProc("GetForegroundWindow")
	procGetConsoleWindow    = modKernel32.NewProc("GetConsoleWindow")
)

const (
	webauthnClientDataVersion1          = 1
	webauthnCredentialExVersion1        = 1
	webauthnGetAssertionOptionsVersion4 = 4 // adds U2F AppId, cancellation and pAllowCredentialList; available since API v1
	webauthnGetAssertionOptionsVersion8 = 8 // adds credential hints; available since API v8
	webauthnAPIVersion8                 = 8

	transportUSB = 0x01
	transportNFC = 0x02
	transportBLE = 0x04

	// Google reauth credentials are physical security keys.
	securityKeyTransports = transportUSB | transportNFC | transportBLE

	uvAny         = 0
	uvRequired    = 1
	uvPreferred   = 2
	uvDiscouraged = 3
)

// WEBAUTHN_CLIENT_DATA
type webauthnClientData struct {
	Version           uint32
	ClientDataJSONLen uint32
	ClientDataJSON    *byte
	HashAlgID         *uint16
}

// WEBAUTHN_CREDENTIAL
type webauthnCredential struct {
	Version        uint32
	IDLen          uint32
	ID             *byte
	CredentialType *uint16
}

// WEBAUTHN_CREDENTIALS
type webauthnCredentials struct {
	Count       uint32
	Credentials *webauthnCredential
}

// WEBAUTHN_CREDENTIAL_EX
type webauthnCredentialEx struct {
	Version        uint32
	IDLen          uint32
	ID             *byte
	CredentialType *uint16
	Transports     uint32
}

// WEBAUTHN_CREDENTIAL_LIST
type webauthnCredentialList struct {
	Count       uint32
	Credentials **webauthnCredentialEx
}

// WEBAUTHN_EXTENSIONS
type webauthnExtensions struct {
	Count      uint32
	Extensions uintptr
}

// WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS, up to version 8.
type webauthnGetAssertionOptions struct {
	Version                     uint32
	TimeoutMilliseconds         uint32
	CredentialList              webauthnCredentials
	Extensions                  webauthnExtensions
	AuthenticatorAttachment     uint32
	UserVerificationRequirement uint32
	Flags                       uint32
	// Version 2
	U2fAppID     *uint16
	U2fAppIDUsed *int32
	// Version 3
	CancellationID *windows.GUID
	// Version 4; when set, CredentialList is ignored.
	AllowCredentialList *webauthnCredentialList
	// Version 5
	CredLargeBlobOperation uint32
	CredLargeBlobLen       uint32
	CredLargeBlob          *byte
	// Version 6
	HmacSecretSaltValues uintptr
	BrowserInPrivateMode int32
	// Version 7
	LinkedDevice uintptr
	AutoFill     int32
	JSONExtLen   uint32
	JSONExt      *byte
	// Version 8
	CredentialHintCount uint32
	CredentialHints     **uint16
}

// WEBAUTHN_ASSERTION, version 1 fields only. Later versions append fields, so
// reading the prefix is safe whatever version Windows returns.
type webauthnAssertion struct {
	Version              uint32
	AuthenticatorDataLen uint32
	AuthenticatorData    *byte
	SignatureLen         uint32
	Signature            *byte
	Credential           webauthnCredential
	UserIDLen            uint32
	UserID               *byte
}

func apiVersion() (uint32, error) {
	if err := procGetApiVersionNumber.Find(); err != nil {
		return 0, fmt.Errorf("Windows WebAuthn API is unavailable (requires Windows 10 1903 or later): %w", err)
	}
	v, _, _ := procGetApiVersionNumber.Call()
	return uint32(v), nil
}

func platformInfo() (string, error) {
	v, err := apiVersion()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Windows WebAuthn API version %d", v), nil
}

func uvRequirement(s string) uint32 {
	switch s {
	case "required":
		return uvRequired
	case "preferred":
		return uvPreferred
	case "discouraged":
		return uvDiscouraged
	}
	return uvAny
}

// parentWindow picks the window the Windows Security dialog is shown over:
// the terminal the user just typed the gcloud command into.
func parentWindow() uintptr {
	if h, _, _ := procGetForegroundWindow.Call(); h != 0 {
		return h
	}
	h, _, _ := procGetConsoleWindow.Call()
	return h
}

func hresultError(hr uintptr) error {
	code := uint32(hr)
	if p, _, _ := procGetErrorName.Call(hr); p != 0 {
		// p is a static string owned by webauthn.dll, not Go memory.
		name := windows.UTF16PtrToString(*(**uint16)(unsafe.Pointer(&p)))
		return fmt.Errorf("%s (HRESULT 0x%08X)", name, code)
	}
	return fmt.Errorf("HRESULT 0x%08X", code)
}

// cancelOnInterrupt cancels the pending operation, closing the Windows
// Security dialog, when the user presses Ctrl+C in the terminal.
func cancelOnInterrupt(id *windows.GUID) (stop func()) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	done := make(chan struct{})
	go func() {
		select {
		case <-sig:
			procCancelCurrentOperation.Call(uintptr(unsafe.Pointer(id)))
		case <-done:
		}
	}()
	return func() {
		signal.Stop(sig)
		close(done)
	}
}

func copyBytes(p *byte, n uint32) []byte {
	if p == nil || n == 0 {
		return nil
	}
	return append([]byte(nil), unsafe.Slice(p, n)...)
}

func platformGetAssertion(req assertionRequest) (*assertion, error) {
	api, err := apiVersion()
	if err != nil {
		return nil, err
	}

	rpID, err := windows.UTF16PtrFromString(req.RPID)
	if err != nil {
		return nil, err
	}
	hashAlg, _ := windows.UTF16PtrFromString("SHA-256")
	credType, _ := windows.UTF16PtrFromString("public-key")

	clientData := webauthnClientData{
		Version:           webauthnClientDataVersion1,
		ClientDataJSONLen: uint32(len(req.ClientDataJSON)),
		ClientDataJSON:    &req.ClientDataJSON[0],
		HashAlgID:         hashAlg,
	}

	opts := webauthnGetAssertionOptions{
		Version:                     webauthnGetAssertionOptionsVersion4,
		TimeoutMilliseconds:         req.TimeoutMs,
		UserVerificationRequirement: uvRequirement(req.UserVerification),
	}

	creds := make([]webauthnCredentialEx, len(req.AllowCredentials))
	credPtrs := make([]*webauthnCredentialEx, len(creds))
	for i, id := range req.AllowCredentials {
		creds[i] = webauthnCredentialEx{
			Version:        webauthnCredentialExVersion1,
			IDLen:          uint32(len(id)),
			ID:             &id[0],
			CredentialType: credType,
			Transports:     securityKeyTransports,
		}
		credPtrs[i] = &creds[i]
	}
	if len(creds) > 0 {
		opts.AllowCredentialList = &webauthnCredentialList{Count: uint32(len(creds)), Credentials: &credPtrs[0]}
	}

	// Windows ignores transports when choosing what to offer, but the
	// "security-key" hint makes it skip the phone / Windows Hello choices.
	if api >= webauthnAPIVersion8 {
		hint, _ := windows.UTF16PtrFromString("security-key")
		hints := []*uint16{hint}
		opts.Version = webauthnGetAssertionOptionsVersion8
		opts.CredentialHintCount = uint32(len(hints))
		opts.CredentialHints = &hints[0]
	}

	// Google's security key credentials are usually legacy U2F registrations
	// scoped to an AppID rather than the RP ID; Windows falls back to it.
	var usedAppID int32
	if req.AppID != "" {
		if opts.U2fAppID, err = windows.UTF16PtrFromString(req.AppID); err != nil {
			return nil, err
		}
		opts.U2fAppIDUsed = &usedAppID
	}

	var cancelID windows.GUID
	if r, _, _ := procGetCancellationId.Call(uintptr(unsafe.Pointer(&cancelID))); r == 0 {
		opts.CancellationID = &cancelID
		defer cancelOnInterrupt(&cancelID)()
	}

	var result *webauthnAssertion
	hr, _, _ := procGetAssertion.Call(
		parentWindow(),
		uintptr(unsafe.Pointer(rpID)),
		uintptr(unsafe.Pointer(&clientData)),
		uintptr(unsafe.Pointer(&opts)),
		uintptr(unsafe.Pointer(&result)),
	)
	if int32(uint32(hr)) < 0 {
		return nil, hresultError(hr)
	}
	if result == nil {
		return nil, errors.New("Windows WebAuthn returned no assertion")
	}
	defer procFreeAssertion.Call(uintptr(unsafe.Pointer(result)))

	return &assertion{
		CredentialID:      copyBytes(result.Credential.ID, result.Credential.IDLen),
		AuthenticatorData: copyBytes(result.AuthenticatorData, result.AuthenticatorDataLen),
		Signature:         copyBytes(result.Signature, result.SignatureLen),
		UserHandle:        copyBytes(result.UserID, result.UserIDLen),
		UsedAppID:         usedAppID != 0,
	}, nil
}
