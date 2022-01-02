package webauthn_sign

import (
	"fmt"
	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"net/http"
)

// PrepareSignatureAssertion prepares data for credentials.get() on browser. Use it only if you want your own
// implementation of sign requests.
func PrepareSignatureAssertion(wa *webauthn.WebAuthn,
	dataHash []byte,
	user webauthn.User) (*protocol.CredentialAssertion, error) {

	if len(dataHash) < 16 || len(dataHash) > 64 {
		return nil, protocol.ErrBadRequest.WithDetails("Invalid data hash length, must be between 16 and 64")
	}
	credentials := user.WebAuthnCredentials()

	if len(credentials) == 0 { // If the user does not have any credentials, we cannot do login
		return nil, protocol.ErrBadRequest.WithDetails("Found no credentials for user")
	}

	var allowedCredentials = make([]protocol.CredentialDescriptor, len(credentials))

	for i, credential := range credentials {
		var credentialDescriptor protocol.CredentialDescriptor
		credentialDescriptor.CredentialID = credential.ID
		credentialDescriptor.Type = protocol.PublicKeyCredentialType
		allowedCredentials[i] = credentialDescriptor
	}

	requestOptions := protocol.PublicKeyCredentialRequestOptions{
		Challenge:          dataHash,
		Timeout:            wa.Config.Timeout,
		RelyingPartyID:     wa.Config.RPID,
		UserVerification:   "discouraged",
		AllowedCredentials: allowedCredentials,
	}
	response := protocol.CredentialAssertion{Response: requestOptions}

	return &response, nil
}

// ParseSignatureCredentialResponse creates signature from CredentialRequestResponse.
func ParseSignatureCredentialResponse(r *http.Request) (*Signature, error) {
	parsedResponse, err := protocol.ParseCredentialRequestResponse(r)
	if nil != err {
		return nil, fmt.Errorf("error while parsing credential request response: %w", err)
	}
	signature := Signature{
		AuthenticatorData: parsedResponse.Raw.AssertionResponse.AuthenticatorData,
		ClientData:        parsedResponse.Raw.AssertionResponse.ClientDataJSON,
		SignatureData:     parsedResponse.Response.Signature,
	}
	return &signature, nil
}
