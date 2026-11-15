package services

import (
	"net/http"
	"time"

	"github.com/safebucket/safebucket/internal/cache"
	"github.com/safebucket/safebucket/internal/configuration"
	apierrors "github.com/safebucket/safebucket/internal/errors"
	wmfa "github.com/safebucket/safebucket/internal/mfa"
	"github.com/safebucket/safebucket/internal/models"
	"github.com/safebucket/safebucket/internal/sql"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func (s MFAService) BeginWebAuthnRegistration(
	logger *zap.Logger,
	claims models.UserClaims,
	_ uuid.UUIDs,
	body models.WebAuthnRegistrationBeginBody,
) (models.WebAuthnRegistrationBeginResponse, error) {
	if claims.AudienceString() != configuration.AudienceAccessToken {
		return models.WebAuthnRegistrationBeginResponse{}, apierrors.New(
			http.StatusForbidden, apierrors.CodeMFASetupRestricted)
	}

	user, err := sql.GetUserByID(s.DB, claims.UserID)
	if err != nil {
		return models.WebAuthnRegistrationBeginResponse{}, err
	}
	if err = s.verifyAddDeviceStepUp(logger, &user, body.Password, body.Code); err != nil {
		return models.WebAuthnRegistrationBeginResponse{}, err
	}

	var count int64
	if err = s.DB.Model(&models.MFADevice{}).Where("user_id = ?", user.ID).Count(&count).Error; err != nil {
		return models.WebAuthnRegistrationBeginResponse{}, err
	}
	if count >= int64(configuration.MaxMFADevicesPerUser) {
		return models.WebAuthnRegistrationBeginResponse{}, apierrors.New(
			http.StatusBadRequest, apierrors.CodeMaxMFADevicesReached)
	}

	var existing int64
	if err = s.DB.Model(&models.MFADevice{}).
		Where("user_id = ? AND name = ?", user.ID, body.Name).
		Count(&existing).Error; err != nil {
		return models.WebAuthnRegistrationBeginResponse{}, err
	}
	if existing > 0 {
		return models.WebAuthnRegistrationBeginResponse{}, apierrors.New(
			http.StatusConflict, apierrors.CodeMFADeviceNameExists)
	}

	var devices []models.MFADevice
	if err = s.DB.Where("user_id = ?", user.ID).Find(&devices).Error; err != nil {
		return models.WebAuthnRegistrationBeginResponse{}, err
	}
	credentials, _, err := wmfa.DecodeWebAuthnCredentials(devices, s.AuthConfig.MFAEncryptionKey)
	if err != nil {
		logger.Error("Failed to decode WebAuthn credentials", zap.Error(err))
		return models.WebAuthnRegistrationBeginResponse{}, apierrors.New(
			http.StatusInternalServerError, apierrors.CodeMFASetupFailed)
	}

	wa, err := wmfa.NewWebAuthn(s.AuthConfig)
	if err != nil {
		logger.Error("Invalid WebAuthn configuration", zap.Error(err))
		return models.WebAuthnRegistrationBeginResponse{}, apierrors.New(
			http.StatusInternalServerError, apierrors.CodeMFASetupFailed)
	}
	waUser := wmfa.NewWebAuthnUser(&user, credentials)
	options, session, err := wa.BeginRegistration(
		waUser,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationPreferred,
		}),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
	)
	if err != nil {
		logger.Error("Failed to begin WebAuthn registration", zap.Error(err))
		return models.WebAuthnRegistrationBeginResponse{}, apierrors.New(
			http.StatusBadRequest, apierrors.CodeMFASetupFailed)
	}

	device := models.MFADevice{
		UserID:          user.ID,
		Name:            body.Name,
		Type:            models.MFADeviceTypeWebAuthn,
		EncryptedSecret: "pending",
		IsVerified:      false,
	}
	if err = s.DB.Create(&device).Error; err != nil {
		return models.WebAuthnRegistrationBeginResponse{}, err
	}
	if err = cache.SetWebAuthnRegistrationSession(s.Cache, device.ID.String(), session); err != nil {
		s.DB.Delete(&device)
		return models.WebAuthnRegistrationBeginResponse{}, apierrors.New(
			http.StatusInternalServerError, apierrors.CodeMFASetupFailed)
	}

	return models.WebAuthnRegistrationBeginResponse{DeviceID: device.ID, Options: options}, nil
}

func (s MFAService) FinishWebAuthnRegistration(
	logger *zap.Logger,
	claims models.UserClaims,
	ids uuid.UUIDs,
	body models.WebAuthnRegistrationFinishBody,
) error {
	if claims.AudienceString() != configuration.AudienceAccessToken {
		return apierrors.New(http.StatusForbidden, apierrors.CodeMFASetupRestricted)
	}
	deviceID := ids[0]
	var device models.MFADevice
	if err := s.DB.Where("id = ? AND user_id = ? AND type = ?", deviceID, claims.UserID,
		models.MFADeviceTypeWebAuthn).First(&device).Error; err != nil {
		return apierrors.New(http.StatusNotFound, apierrors.CodeMFADeviceNotFound)
	}
	if device.IsVerified {
		return apierrors.New(http.StatusConflict, apierrors.CodeMFADeviceAlreadyVerified)
	}

	session, found, err := cache.GetWebAuthnRegistrationSession[webauthn.SessionData](s.Cache, deviceID.String())
	if err != nil || !found {
		return apierrors.New(http.StatusBadRequest, apierrors.CodeMFAVerificationFailed)
	}
	defer func() {
		if deleteErr := cache.DeleteWebAuthnRegistrationSession(s.Cache, deviceID.String()); deleteErr != nil {
			logger.Warn("Failed to delete WebAuthn registration session", zap.Error(deleteErr))
		}
	}()

	user, err := sql.GetUserByID(s.DB, claims.UserID)
	if err != nil {
		return err
	}
	var devices []models.MFADevice
	if err = s.DB.Where("user_id = ?", user.ID).Find(&devices).Error; err != nil {
		return err
	}
	credentials, _, err := wmfa.DecodeWebAuthnCredentials(devices, s.AuthConfig.MFAEncryptionKey)
	if err != nil {
		return apierrors.New(http.StatusInternalServerError, apierrors.CodeMFAVerificationFailed)
	}

	parsed, err := protocol.ParseCredentialCreationResponseBytes(body.Credential)
	if err != nil {
		return apierrors.New(http.StatusBadRequest, apierrors.CodeMFAVerificationFailed)
	}
	wa, err := wmfa.NewWebAuthn(s.AuthConfig)
	if err != nil {
		return apierrors.New(http.StatusInternalServerError, apierrors.CodeMFAVerificationFailed)
	}
	credential, err := wa.CreateCredential(wmfa.NewWebAuthnUser(&user, credentials), session, parsed)
	if err != nil {
		logger.Warn("WebAuthn registration verification failed", zap.Error(err))
		return apierrors.New(http.StatusUnauthorized, apierrors.CodeMFAVerificationFailed)
	}
	encrypted, err := wmfa.EncodeWebAuthnCredential(credential, s.AuthConfig.MFAEncryptionKey)
	if err != nil {
		return apierrors.New(http.StatusInternalServerError, apierrors.CodeMFAVerificationFailed)
	}

	return s.DB.Transaction(func(tx *gorm.DB) error {
		var locked models.MFADevice
		if txErr := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ? AND user_id = ?", deviceID, user.ID).First(&locked).Error; txErr != nil {
			return txErr
		}
		var defaultCount int64
		if txErr := tx.Model(&models.MFADevice{}).
			Where("user_id = ? AND is_verified = ? AND is_default = ?", user.ID, true, true).
			Count(&defaultCount).Error; txErr != nil {
			return txErr
		}
		now := time.Now()
		return tx.Model(&locked).Updates(map[string]any{
			"encrypted_secret": encrypted,
			"is_verified":      true,
			"is_default":       defaultCount == 0,
			"verified_at":      now,
			"last_used_at":     now,
		}).Error
	})
}
