//go:build !windows

package main

import "errors"

var errUnsupported = errors.New("gcloud-webauthn only supports Windows")

func platformInfo() (string, error) { return "", errUnsupported }

func platformGetAssertion(assertionRequest) (*assertion, error) { return nil, errUnsupported }
