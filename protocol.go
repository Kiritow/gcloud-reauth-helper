package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// google-auth (google/oauth2/challenges.py) always uses this origin for
// security key reauth, and the plugin refuses to sign for anything else.
const reauthOrigin = "https://accounts.google.com"

const (
	maxMessageSize   = 1 << 20
	defaultTimeoutMs = 120000
)

// getRequest mirrors GetRequest.to_json() in google/oauth2/webauthn_types.py.
type getRequest struct {
	Type        string      `json:"type"`
	Origin      string      `json:"origin"`
	RequestData requestData `json:"requestData"`
}

type requestData struct {
	RPID             string                 `json:"rpid"`
	Challenge        string                 `json:"challenge"`
	Timeout          uint32                 `json:"timeout"`
	AllowCredentials []credentialDescriptor `json:"allowCredentials"`
	UserVerification string                 `json:"userVerification"`
	Extensions       struct {
		AppID string `json:"appid"`
	} `json:"extensions"`
}

type credentialDescriptor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// getResponse is parsed by GetResponse.from_json() in webauthn_types.py.
type getResponse struct {
	Type         string               `json:"type"`
	ResponseData *publicKeyCredential `json:"responseData,omitempty"`
	Error        string               `json:"error,omitempty"`
}

type publicKeyCredential struct {
	Type                   string            `json:"type"`
	ID                     string            `json:"id"`
	RawID                  string            `json:"rawId"`
	Response               assertionResponse `json:"response"`
	ClientExtensionResults map[string]any    `json:"clientExtensionResults"`
}

type assertionResponse struct {
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle,omitempty"`
}

// collectedClientData is the CollectedClientData dictionary from the WebAuthn
// spec. Field order matches what browsers emit.
type collectedClientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

// assertionRequest is what the platform authenticator needs to sign.
type assertionRequest struct {
	RPID             string
	ClientDataJSON   []byte
	AllowCredentials [][]byte
	AppID            string
	TimeoutMs        uint32
	UserVerification string
}

type assertion struct {
	CredentialID      []byte
	AuthenticatorData []byte
	Signature         []byte
	UserHandle        []byte
	UsedAppID         bool
}

type authenticator func(assertionRequest) (*assertion, error)

func readMessage(r io.Reader) ([]byte, error) {
	var size uint32
	if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
		return nil, fmt.Errorf("reading message length: %w", err)
	}
	if size > maxMessageSize {
		return nil, fmt.Errorf("message too large: %d bytes", size)
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("reading message body: %w", err)
	}
	return buf, nil
}

func writeMessage(w io.Writer, msg []byte) error {
	if err := binary.Write(w, binary.LittleEndian, uint32(len(msg))); err != nil {
		return err
	}
	_, err := w.Write(msg)
	return err
}

// decodeB64 accepts both base64url and standard base64, padded or not.
func decodeB64(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	s = strings.NewReplacer("+", "-", "/", "_").Replace(s)
	return base64.RawURLEncoding.DecodeString(s)
}

func encodeB64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// validRPID reports whether rpID is a registrable suffix of the origin's host,
// as the WebAuthn spec requires of a client.
func validRPID(rpID, origin string) bool {
	host := strings.TrimPrefix(origin, "https://")
	return rpID != "" && (host == rpID || strings.HasSuffix(host, "."+rpID))
}

func buildAssertionRequest(req *getRequest) (assertionRequest, error) {
	if req.Type != "get" {
		return assertionRequest{}, fmt.Errorf("unsupported request type %q", req.Type)
	}
	if req.Origin != reauthOrigin {
		return assertionRequest{}, fmt.Errorf("refusing origin %q", req.Origin)
	}
	rd := req.RequestData
	if !validRPID(rd.RPID, req.Origin) {
		return assertionRequest{}, fmt.Errorf("rpid %q is not valid for origin %q", rd.RPID, req.Origin)
	}
	challenge, err := decodeB64(rd.Challenge)
	if err != nil || len(challenge) == 0 {
		return assertionRequest{}, errors.New("missing or malformed challenge")
	}
	clientData, err := json.Marshal(collectedClientData{
		Type:      "webauthn.get",
		Challenge: encodeB64(challenge),
		Origin:    req.Origin,
	})
	if err != nil {
		return assertionRequest{}, err
	}

	out := assertionRequest{
		RPID:             rd.RPID,
		ClientDataJSON:   clientData,
		AppID:            rd.Extensions.AppID,
		TimeoutMs:        rd.Timeout,
		UserVerification: rd.UserVerification,
	}
	if out.TimeoutMs == 0 {
		out.TimeoutMs = defaultTimeoutMs
	}
	for _, c := range rd.AllowCredentials {
		id, err := decodeB64(c.ID)
		if err != nil || len(id) == 0 {
			return assertionRequest{}, errors.New("malformed credential id in allowCredentials")
		}
		out.AllowCredentials = append(out.AllowCredentials, id)
	}
	return out, nil
}

func buildResponse(req assertionRequest, a *assertion) *getResponse {
	cred := &publicKeyCredential{
		Type:  "public-key",
		ID:    encodeB64(a.CredentialID),
		RawID: encodeB64(a.CredentialID),
		Response: assertionResponse{
			ClientDataJSON:    encodeB64(req.ClientDataJSON),
			AuthenticatorData: encodeB64(a.AuthenticatorData),
			Signature:         encodeB64(a.Signature),
		},
		ClientExtensionResults: map[string]any{},
	}
	if len(a.UserHandle) > 0 {
		cred.Response.UserHandle = encodeB64(a.UserHandle)
	}
	if req.AppID != "" {
		cred.ClientExtensionResults["appid"] = a.UsedAppID
	}
	return &getResponse{Type: "getResponse", ResponseData: cred}
}

func handle(msg []byte, getAssertion authenticator) *getResponse {
	var req getRequest
	if err := json.Unmarshal(msg, &req); err != nil {
		return &getResponse{Type: "getResponse", Error: "malformed request: " + err.Error()}
	}
	ar, err := buildAssertionRequest(&req)
	if err != nil {
		return &getResponse{Type: "getResponse", Error: err.Error()}
	}
	a, err := getAssertion(ar)
	if err != nil {
		return &getResponse{Type: "getResponse", Error: err.Error()}
	}
	return buildResponse(ar, a)
}

// serve handles one request/response exchange. Failures are reported to
// google-auth inside the response so it can print them; only I/O failures are
// returned as errors.
func serve(r io.Reader, w io.Writer, getAssertion authenticator) error {
	var resp *getResponse
	if msg, err := readMessage(r); err != nil {
		resp = &getResponse{Type: "getResponse", Error: err.Error()}
	} else {
		resp = handle(msg, getAssertion)
	}
	out, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	return writeMessage(w, out)
}
