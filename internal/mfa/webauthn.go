package mfa

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"

	h "github.com/safebucket/safebucket/internal/helpers"
	"github.com/safebucket/safebucket/internal/models"

	"github.com/go-webauthn/webauthn/webauthn"
)

type WebAuthnUser struct {
	ID          []byte
	Name        string
	Credentials []webauthn.Credential
}

func (u WebAuthnUser) WebAuthnID() []byte                         { return u.ID }
func (u WebAuthnUser) WebAuthnName() string                       { return u.Name }
func (u WebAuthnUser) WebAuthnDisplayName() string                { return u.Name }
func (u WebAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

func NewWebAuthn(config models.AuthConfig) (*webauthn.WebAuthn, error) {
	webURL, err := url.Parse(config.WebURL)
	if err != nil || webURL.Scheme == "" || webURL.Hostname() == "" {
		return nil, fmt.Errorf("invalid WebAuthn web URL %q", config.WebURL)
	}
	origin := webURL.Scheme + "://" + webURL.Host
	return webauthn.New(&webauthn.Config{
		RPID:          webURL.Hostname(),
		RPDisplayName: "Safebucket",
		RPOrigins:     []string{origin},
	})
}

func NewWebAuthnUser(user *models.User, credentials []webauthn.Credential) WebAuthnUser {
	return WebAuthnUser{
		ID:          user.ID[:],
		Name:        user.Email,
		Credentials: credentials,
	}
}

func DecodeWebAuthnCredentials(
	devices []models.MFADevice,
	encryptionKey string,
) ([]webauthn.Credential, map[string]*models.MFADevice, error) {
	credentials := make([]webauthn.Credential, 0)
	byCredentialID := make(map[string]*models.MFADevice)
	for i := range devices {
		device := &devices[i]
		if device.Type != models.MFADeviceTypeWebAuthn || !device.IsVerified {
			continue
		}
		plaintext, err := h.DecryptSecret(device.EncryptedSecret, []byte(encryptionKey))
		if err != nil {
			return nil, nil, err
		}
		var credential webauthn.Credential
		if err = json.Unmarshal([]byte(plaintext), &credential); err != nil {
			return nil, nil, err
		}
		credentials = append(credentials, credential)
		byCredentialID[base64.RawURLEncoding.EncodeToString(credential.ID)] = device
	}
	return credentials, byCredentialID, nil
}

func EncodeWebAuthnCredential(credential *webauthn.Credential, encryptionKey string) (string, error) {
	payload, err := json.Marshal(credential)
	if err != nil {
		return "", err
	}
	return h.EncryptSecret(string(payload), []byte(encryptionKey))
}
