package webauthn_sign

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/protocol/webauthncose"
)

// Signature represents document hash signature object. Unlike normal ECDSA signature, it also carries
// some extra information (AuthenticatorData and ClientData), which is necessary to be hashed together
// with user data to check correctness of WebAuthn signature.
type Signature struct {
	AuthenticatorData protocol.URLEncodedBase64 `json:"a"`
	ClientData        protocol.URLEncodedBase64 `json:"c"`
	SignatureData     protocol.URLEncodedBase64 `json:"s"`
}

// Verify data against the signature, provided COSE-encoded public key. Public key can be obtained
// during registration process as Credential.PubKey.
//
// dataHash should be between 16 and 64 bytes long.
func (signature *Signature) Verify(pubKey []byte, dataHash []byte) (bool, error) {

	collectedClientData := protocol.CollectedClientData{}
	if err := json.Unmarshal(signature.ClientData, &collectedClientData); nil != err {
		return false, fmt.Errorf("error while unmarshalling ClientData: %w", err)
	}
	var challenge protocol.URLEncodedBase64
	if err := challenge.UnmarshalJSON([]byte(collectedClientData.Challenge)); nil != err {
		return false, fmt.Errorf("error while unmarshalling challenge: %w", err)
	}
	// Compare signature hash with saved challenge. Saved challenge can't be tampered with
	// because it is a part of ClientData, which is hashed before verifying signature.
	if 0 != bytes.Compare(challenge, dataHash) {
		return false, nil
	}
	clientDataHash := sha256.Sum256(signature.ClientData)
	sigData := append(signature.AuthenticatorData, clientDataHash[:]...)

	key, err := webauthncose.ParsePublicKey(pubKey)
	if nil != err {
		return false, fmt.Errorf("PubKey parse error: %w", err)
	}
	if isValid, err := webauthncose.VerifySignature(key, sigData, signature.SignatureData); nil != err {
		return false, fmt.Errorf("VerifySignature error: %w", err)
	} else {
		return isValid, nil
	}
}

// VerifySha256 hashes data with SHA256 before passing it to Verify().
func (signature *Signature) VerifySha256(pubKey []byte, data []byte) (bool, error) {
	dataHash := sha256.Sum256(data)
	return signature.Verify(pubKey, dataHash[:])
}
