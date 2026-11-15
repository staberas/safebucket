package models

import (
	"encoding/json"

	"github.com/google/uuid"
)

type WebAuthnRegistrationBeginBody struct {
	Name     string `json:"name"     validate:"required,min=1,max=50"`
	Password string `json:"password" validate:"omitempty"`
	Code     string `json:"code"     validate:"omitempty,len=6,numeric"`
}

type WebAuthnRegistrationBeginResponse struct {
	DeviceID uuid.UUID `json:"device_id"`
	Options  any       `json:"options"`
}

type WebAuthnRegistrationFinishBody struct {
	Credential json.RawMessage `json:"credential" validate:"required"`
}

type WebAuthnLoginBeginBody struct {
	DeviceID *uuid.UUID `json:"device_id" validate:"omitempty"`
}

type WebAuthnLoginBeginResponse struct {
	ChallengeID uuid.UUID `json:"challenge_id"`
	Options     any       `json:"options"`
}

type WebAuthnLoginFinishBody struct {
	ChallengeID uuid.UUID       `json:"challenge_id" validate:"required"`
	Credential  json.RawMessage `json:"credential"   validate:"required"`
}
