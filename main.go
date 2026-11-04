// Command gcloud-webauthn is a WebAuthn plugin for google-auth's
// GOOGLE_AUTH_WEBAUTHN_PLUGIN hook. It answers gcloud's security key reauth
// challenges through the Windows WebAuthn API (webauthn.dll), which talks to
// FIDO2 / U2F keys without administrator rights.
//
// google-auth starts the plugin once per challenge and exchanges a single
// message in each direction over stdin/stdout, framed as a 4-byte
// little-endian length followed by a JSON payload.
package main

import (
	"flag"
	"fmt"
	"os"
)

// google-auth always requests userVerification "required", which makes
// Windows ask for the security key PIN. Google accepts assertions without it,
// so default to "discouraged" (touch only, like pyu2f) unless uvOverrideEnv
// says otherwise.
const (
	uvOverrideEnv           = "GCLOUD_WEBAUTHN_USER_VERIFICATION"
	defaultUserVerification = "discouraged"
)

func main() {
	check := flag.Bool("check", false, "report whether the Windows WebAuthn API is available, then exit")
	flag.Parse()

	if *check {
		info, err := platformInfo()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(info)
		return
	}

	uv := os.Getenv(uvOverrideEnv)
	if uv == "" {
		uv = defaultUserVerification
	}
	getAssertion := func(r assertionRequest) (*assertion, error) {
		r.UserVerification = uv
		return platformGetAssertion(r)
	}

	if err := serve(os.Stdin, os.Stdout, getAssertion); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
