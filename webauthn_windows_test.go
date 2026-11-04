//go:build windows && (amd64 || arm64)

package main

import (
	"testing"
	"unsafe"
)

// Offsets from webauthn.h as laid out by MSVC on 64-bit Windows.
func TestStructLayout(t *testing.T) {
	var o webauthnGetAssertionOptions
	var a webauthnAssertion
	checks := []struct {
		name      string
		got, want uintptr
	}{
		{"sizeof(WEBAUTHN_CLIENT_DATA)", unsafe.Sizeof(webauthnClientData{}), 24},
		{"sizeof(WEBAUTHN_CREDENTIAL)", unsafe.Sizeof(webauthnCredential{}), 24},
		{"sizeof(WEBAUTHN_CREDENTIAL_EX)", unsafe.Sizeof(webauthnCredentialEx{}), 32},
		{"sizeof(WEBAUTHN_CREDENTIAL_LIST)", unsafe.Sizeof(webauthnCredentialList{}), 16},
		{"options.CredentialList", unsafe.Offsetof(o.CredentialList), 8},
		{"options.Extensions", unsafe.Offsetof(o.Extensions), 24},
		{"options.dwAuthenticatorAttachment", unsafe.Offsetof(o.AuthenticatorAttachment), 40},
		{"options.dwFlags", unsafe.Offsetof(o.Flags), 48},
		{"options.pwszU2fAppId", unsafe.Offsetof(o.U2fAppID), 56},
		{"options.pCancellationId", unsafe.Offsetof(o.CancellationID), 72},
		{"options.pAllowCredentialList", unsafe.Offsetof(o.AllowCredentialList), 80},
		{"options.pbCredLargeBlob", unsafe.Offsetof(o.CredLargeBlob), 96},
		{"options.bBrowserInPrivateMode", unsafe.Offsetof(o.BrowserInPrivateMode), 112},
		{"options.pLinkedDevice", unsafe.Offsetof(o.LinkedDevice), 120},
		{"options.pbJsonExt", unsafe.Offsetof(o.JSONExt), 136},
		{"options.cCredentialHints", unsafe.Offsetof(o.CredentialHintCount), 144},
		{"options.ppwszCredentialHints", unsafe.Offsetof(o.CredentialHints), 152},
		{"sizeof(options v8)", unsafe.Sizeof(o), 160},
		{"assertion.pbSignature", unsafe.Offsetof(a.Signature), 24},
		{"assertion.Credential", unsafe.Offsetof(a.Credential), 32},
		{"assertion.pbUserId", unsafe.Offsetof(a.UserID), 64},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestAPIAvailable(t *testing.T) {
	v, err := apiVersion()
	if err != nil {
		t.Skip(err)
	}
	t.Logf("Windows WebAuthn API version %d", v)
}
