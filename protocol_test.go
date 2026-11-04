package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const appID = "https://www.gstatic.com/securitykey/origins.json"

// googleAuthRequest is what GetRequest.to_json() produces for a reauth
// challenge (challenge "challenge", key handles "kh1" and "kh2").
const googleAuthRequest = `{"type": "get", "origin": "https://accounts.google.com", "requestData": {"rpid": "google.com", "challenge": "Y2hhbGxlbmdl", "timeout": 120000, "allowCredentials": [{"type": "public-key", "id": "a2gx"}, {"type": "public-key", "id": "a2gy"}], "userVerification": "required", "extensions": {"appid": "https://www.gstatic.com/securitykey/origins.json"}}}`

func frame(s string) *bytes.Reader {
	var buf bytes.Buffer
	writeMessage(&buf, []byte(s))
	return bytes.NewReader(buf.Bytes())
}

func roundTrip(t *testing.T, in *bytes.Reader, auth authenticator) map[string]any {
	t.Helper()
	var out bytes.Buffer
	if err := serve(in, &out, auth); err != nil {
		t.Fatalf("serve: %v", err)
	}
	var size uint32
	binary.Read(&out, binary.LittleEndian, &size)
	if int(size) != out.Len() {
		t.Fatalf("length prefix %d, body %d bytes", size, out.Len())
	}
	var resp map[string]any
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if resp["type"] != "getResponse" {
		t.Fatalf("type = %v, want getResponse", resp["type"])
	}
	return resp
}

func TestGetAssertion(t *testing.T) {
	var got assertionRequest
	auth := func(r assertionRequest) (*assertion, error) {
		got = r
		return &assertion{
			CredentialID:      []byte("kh2"),
			AuthenticatorData: []byte("authdata"),
			Signature:         []byte("sig"),
			UsedAppID:         true,
		}, nil
	}
	resp := roundTrip(t, frame(googleAuthRequest), auth)

	wantClientData := `{"type":"webauthn.get","challenge":"Y2hhbGxlbmdl","origin":"https://accounts.google.com","crossOrigin":false}`
	if string(got.ClientDataJSON) != wantClientData {
		t.Errorf("clientDataJSON = %s, want %s", got.ClientDataJSON, wantClientData)
	}
	if got.RPID != "google.com" || got.AppID != appID || got.TimeoutMs != 120000 || got.UserVerification != "required" {
		t.Errorf("unexpected request: %+v", got)
	}
	if len(got.AllowCredentials) != 2 || string(got.AllowCredentials[0]) != "kh1" || string(got.AllowCredentials[1]) != "kh2" {
		t.Errorf("allowCredentials = %q", got.AllowCredentials)
	}

	if resp["error"] != nil {
		t.Fatalf("unexpected error: %v", resp["error"])
	}
	// Fields read by GetResponse.from_json() in google/oauth2/webauthn_types.py.
	cred := resp["responseData"].(map[string]any)
	if cred["type"] != "public-key" || cred["id"] != "a2gy" {
		t.Errorf("credential = %v", cred)
	}
	ar := cred["response"].(map[string]any)
	if ar["clientDataJSON"] != encodeB64([]byte(wantClientData)) ||
		ar["authenticatorData"] != encodeB64([]byte("authdata")) ||
		ar["signature"] != encodeB64([]byte("sig")) {
		t.Errorf("response = %v", ar)
	}
	if _, ok := ar["userHandle"]; ok {
		t.Errorf("userHandle should be omitted when empty")
	}
	if ext := cred["clientExtensionResults"].(map[string]any); ext["appid"] != true {
		t.Errorf("clientExtensionResults = %v", ext)
	}
}

func TestErrorsAreReportedInResponse(t *testing.T) {
	never := func(assertionRequest) (*assertion, error) {
		t.Fatal("authenticator should not be called")
		return nil, nil
	}
	tests := []struct {
		name    string
		in      *bytes.Reader
		auth    authenticator
		wantErr string
	}{
		{"wrong origin", frame(strings.Replace(googleAuthRequest, "accounts.google.com", "evil.example", 1)), never, "refusing origin"},
		{"rpid outside origin", frame(strings.Replace(googleAuthRequest, `"google.com"`, `"evil.example"`, 1)), never, "rpid"},
		{"rpid suffix trick", frame(strings.Replace(googleAuthRequest, `"google.com"`, `"gle.com"`, 1)), never, "rpid"},
		{"not a get", frame(`{"type":"create"}`), never, "unsupported request type"},
		{"bad json", frame(`{`), never, "malformed request"},
		{"truncated", bytes.NewReader([]byte{10, 0, 0, 0, '{'}), never, "reading message body"},
		{"too large", bytes.NewReader([]byte{0, 0, 0, 1}), never, "too large"},
		{"authenticator failure", frame(googleAuthRequest), func(assertionRequest) (*assertion, error) {
			return nil, errors.New("NotAllowedError")
		}, "NotAllowedError"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := roundTrip(t, tt.in, tt.auth)
			if resp["responseData"] != nil {
				t.Fatalf("unexpected responseData")
			}
			if msg, _ := resp["error"].(string); !strings.Contains(msg, tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", msg, tt.wantErr)
			}
		})
	}
}

func TestDecodeB64(t *testing.T) {
	for _, s := range []string{"-_8", "+/8=", "+/8"} {
		b, err := decodeB64(s)
		if err != nil || !bytes.Equal(b, []byte{0xfb, 0xff}) {
			t.Errorf("decodeB64(%q) = %x, %v", s, b, err)
		}
	}
}
