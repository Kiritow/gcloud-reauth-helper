# gcloud-webauthn

A google-auth WebAuthn plugin that answers gcloud's security key reauth
challenges through the Windows WebAuthn API (`webauthn.dll`) instead of
pyu2f's raw HID access.

- No administrator rights / UAC: since Windows 10 1903, only `webauthn.dll`
  may talk to FIDO devices as a normal user.
- Works with FIDO2 keys (Titan, YubiKey 5, …) over USB, NFC and BLE.
- Single static exe, no Python runtime, no dependencies besides `golang.org/x/sys`.

## Why the Cloud SDK does not need patching

The SDK's bundled google-auth (`lib/third_party/google/oauth2/challenges.py`)
already checks the `GOOGLE_AUTH_WEBAUTHN_PLUGIN` environment variable before
falling back to pyu2f. When it is set, `SecurityKeyChallenge` runs that
executable and exchanges one message each way over stdin/stdout:

```
[4 bytes: payload length, little-endian][JSON payload]
```

Request (`webauthn_types.GetRequest.to_json`):

```json
{"type": "get", "origin": "https://accounts.google.com",
 "requestData": {"rpid": "google.com", "challenge": "<b64url>", "timeout": 120000,
                 "allowCredentials": [{"type": "public-key", "id": "<b64url>"}],
                 "userVerification": "required",
                 "extensions": {"appid": "https://www.gstatic.com/securitykey/origins.json"}}}
```

Response (`webauthn_types.GetResponse.from_json`):

```json
{"type": "getResponse",
 "responseData": {"type": "public-key", "id": "<b64url>", "rawId": "<b64url>",
                  "response": {"clientDataJSON": "...", "authenticatorData": "...", "signature": "..."},
                  "clientExtensionResults": {"appid": true}}}
```

or `{"type": "getResponse", "error": "..."}` on failure.

Because nothing in the SDK is modified, `gcloud components update` will not undo it.
(Verified against Cloud SDK 565.0.0.)

## Build

```powershell
go test ./...
go build -trimpath -ldflags "-s -w" -o gcloud-webauthn.exe .
.\gcloud-webauthn.exe -check   # prints the Windows WebAuthn API version
```

## Install

Copy the exe somewhere only you can write to and point google-auth at it:

```powershell
$dir = "$env:LOCALAPPDATA\Programs\gcloud-webauthn"
New-Item -ItemType Directory -Force $dir | Out-Null
Copy-Item .\gcloud-webauthn.exe $dir
[Environment]::SetEnvironmentVariable("GOOGLE_AUTH_WEBAUTHN_PLUGIN", "$dir\gcloud-webauthn.exe", "User")
```

Open a new terminal (the variable only reaches newly started processes) and run
gcloud **without** "Run as administrator". On the next reauth, gcloud prints
"Please insert and touch your security key" and the Windows Security dialog
appears.

To uninstall, remove the variable:

```powershell
[Environment]::SetEnvironmentVariable("GOOGLE_AUTH_WEBAUTHN_PLUGIN", $null, "User")
```

## Behaviour and troubleshooting

- **The plugin only signs for `https://accounts.google.com`** and an RP ID that
  is a suffix of it (`google.com`). Anything else is rejected before any UI
  is shown.
- **Errors fall back to pyu2f.** If the plugin returns an error, google-auth
  prints `Webauthn Error: ...` and then silently tries pyu2f, which (without
  admin) usually ends with "No security key found". Read the `Webauthn Error`
  line for the real cause, e.g. `NotAllowedError` when the dialog was cancelled
  or timed out.
- **Touch only, no PIN, by default.** google-auth requests
  `userVerification: "required"`, which would make Windows ask for the
  security key PIN. Google accepts assertions without it, so the plugin sends
  `discouraged` instead: the same touch-only check pyu2f did. Set
  `GCLOUD_WEBAUTHN_USER_VERIFICATION=required` (or `preferred`) to get the
  PIN prompt back.
- **Straight to the security key.** On Windows WebAuthn API v8+ (check with
  `-check`) the plugin sends the `security-key` credential hint, so the
  dialog skips the "iPhone, iPad or Android device" and Windows Hello choices.
  Restricting the credentials' transports to USB/NFC/BLE alone does not hide
  them. On older Windows builds the hint is not available and the full chooser
  appears.
- **Ctrl+C** in the terminal cancels the pending request and closes the dialog.
- The dialog is parented to the foreground window (your terminal). If it opens
  behind other windows, check the taskbar.
