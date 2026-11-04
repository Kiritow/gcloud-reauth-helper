"""Windows WebAuthn plugin for google-auth's GOOGLE_AUTH_WEBAUTHN_PLUGIN hook.

Install on Windows (Python 3.10+):
    python -m pip install 'fido2>=2,<3' pyinstaller
    python -m PyInstaller --onefile --console --name gcloud-webauthn gcloud_webauthn_plugin.py

Set GOOGLE_AUTH_WEBAUTHN_PLUGIN to the resulting dist\\gcloud-webauthn.exe.
Keep this executable under your control and follow your organization's software policy.
"""

import json
import struct
import sys


def read_request():
    header = sys.stdin.buffer.read(4)
    if len(header) != 4:
        raise ValueError("Missing 4-byte message length")
    (size,) = struct.unpack("<I", header)
    if size > 1024 * 1024:
        raise ValueError("Request too large")
    raw = sys.stdin.buffer.read(size)
    if len(raw) != size:
        raise ValueError("Truncated request")
    return json.loads(raw.decode("utf-8"))


def get_response(request):
    # Google uses a fixed origin for its Cloud SDK security-key challenges.
    if request.get("type") != "get":
        raise ValueError("Unexpected operation")
    origin = request.get("origin")
    if origin != "https://accounts.google.com":
        raise ValueError("Unexpected WebAuthn origin")

    from fido2.client import DefaultClientDataCollector
    from fido2.client.windows import WindowsClient

    if not WindowsClient.is_available():
        raise RuntimeError("Windows WebAuthn API is unavailable")

    client = WindowsClient(DefaultClientDataCollector(origin))
    selection = client.get_assertion(request["requestData"])
    assertion = selection.get_response(0)
    return {"type": "getResponse", "responseData": dict(assertion)}


def write_response(response):
    raw = json.dumps(response, separators=(",", ":")).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("<I", len(raw)))
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()


def main():
    try:
        response = get_response(read_request())
    except Exception as exc:
        # Return a protocol-level error without emitting credentials or challenges.
        response = {"type": "getResponse", "error": f"{type(exc).__name__}: {exc}"}
    write_response(response)


if __name__ == "__main__":
    main()
