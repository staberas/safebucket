package services

import (
	"encoding/base64"
	"net/http"
	"time"

	"github.com/safebucket/safebucket/internal/cache"
	"github.com/safebucket/safebucket/internal/configuration"
	apierrors "github.com/safebucket/safebucket/internal/errors"
	"github.com/safebucket/safebucket/internal/handlers"
	wmfa "github.com/safebucket/safebucket/internal/mfa"
	"github.com/safebucket/safebucket/internal/models"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

func (s AuthService) BeginWebAuthnLogin(
	logger *zap.Logger,
	claims models.UserClaims,
	_ uuid.UUIDs,
	body models.WebAuthnLoginBeginBody,
) (models.WebAuthnLoginBeginResponse, error) {
	if claims.AudienceString() != configuration.AudienceMFALogin {
		return models.WebAuthnLoginBeginResponse{}, apierrors.New(
			http.StatusForbidden, apierrors.CodeForbidden)
	}

	attempts, err := cache.GetMFAAttempts(s.Cache, claims.UserID.String())
	if err != nil {
		return models.WebAuthnLoginBeginResponse{}, apierrors.New(
			http.StatusServiceUnavailable, apierrors.CodeServiceUnavailable)
	}
	if attempts >= configuration.MFAMaxAttempts {
		return models.WebAuthnLoginBeginResponse{}, apierrors.New(
			http.StatusTooManyRequests, apierrors.CodeMFARateLimited)
	}

	var user models.User
	if err = s.DB.Preload("MFADevices", "is_verified = ?", true).
		Where("id = ?", claims.UserID).First(&user).Error; err != nil {
		return models.WebAuthnLoginBeginResponse{}, apierrors.New(
			http.StatusNotFound, apierrors.CodeUserNotFound)
	}

	devices := user.MFADevices
	if body.DeviceID != nil {
		filtered := make([]models.MFADevice, 0, 1)
		for i := range devices {
			if devices[i].ID == *body.DeviceID && devices[i].Type == models.MFADeviceTypeWebAuthn {
				filtered = append(filtered, devices[i])
				break
			}
		}
		if len(filtered) == 0 {
			return models.WebAuthnLoginBeginResponse{}, apierrors.New(
				http.StatusNotFound, apierrors.CodeMFADeviceNotFound)
		}
		devices = filtered
	}

	credentials, _, err := wmfa.DecodeWebAuthnCredentials(devices, s.AuthConfig.MFAEncryptionKey)
	if err != nil || len(credentials) == 0 {
		return models.WebAuthnLoginBeginResponse{}, apierrors.New(
			http.StatusBadRequest, apierrors.CodeMFADeviceNotFound)
	}
	wa, err := wmfa.NewWebAuthn(s.AuthConfig)
	if err != nil {
		logger.Error("Invalid WebAuthn configuration", zap.Error(err))
		return models.WebAuthnLoginBeginResponse{}, apierrors.New(
			http.StatusInternalServerError, apierrors.CodeMFAVerificationFailed)
	}
	options, session, err := wa.BeginLogin(
		wmfa.NewWebAuthnUser(&user, credentials),
		webauthn.WithUserVerification(protocol.VerificationPreferred),
	)
	if err != nil {
		return models.WebAuthnLoginBeginResponse{}, apierrors.New(
			http.StatusBadRequest, apierrors.CodeMFAVerificationFailed)
	}

	challengeID := uuid.New()
	if err = cache.SetWebAuthnLoginSession(s.Cache, challengeID.String(), session); err != nil {
		return models.WebAuthnLoginBeginResponse{}, apierrors.New(
			http.StatusInternalServerError, apierrors.CodeMFAVerificationFailed)
	}
	return models.WebAuthnLoginBeginResponse{ChallengeID: challengeID, Options: options}, nil
}

func (s AuthService) FinishWebAuthnLogin(
	isSecure bool,
	logger *zap.Logger,
	claims models.UserClaims,
	_ uuid.UUIDs,
	body models.WebAuthnLoginFinishBody,
) (handlers.AuthFlowResult, error) {
	if claims.AudienceString() != configuration.AudienceMFALogin {
		return handlers.AuthFlowResult{}, apierrors.New(http.StatusForbidden, apierrors.CodeForbidden)
	}

	session, found, err := cache.GetWebAuthnLoginSession[webauthn.SessionData](
		s.Cache, body.ChallengeID.String())
	if err != nil || !found {
		return handlers.AuthFlowResult{}, apierrors.New(
			http.StatusBadRequest, apierrors.CodeMFAVerificationFailed)
	}
	defer func() {
		if deleteErr := cache.DeleteWebAuthnLoginSession(s.Cache, body.ChallengeID.String()); deleteErr != nil {
			logger.Warn("Failed to delete WebAuthn login session", zap.Error(deleteErr))
		}
	}()

	var user models.User
	if err = s.DB.Preload("MFADevices", "is_verified = ?", true).
		Where("id = ?", claims.UserID).First(&user).Error; err != nil {
		return handlers.AuthFlowResult{}, apierrors.New(http.StatusNotFound, apierrors.CodeUserNotFound)
	}
	credentials, byCredentialID, err := wmfa.DecodeWebAuthnCredentials(
		user.MFADevices, s.AuthConfig.MFAEncryptionKey)
	if err != nil || len(credentials) == 0 {
		return handlers.AuthFlowResult{}, apierrors.New(
			http.StatusBadRequest, apierrors.CodeMFADeviceNotFound)
	}

	parsed, err := protocol.ParseCredentialRequestResponseBytes(body.Credential)
	if err != nil {
		s.recordWebAuthnFailure(logger, user.ID)
		return handlers.AuthFlowResult{}, apierrors.New(
			http.StatusUnauthorized, apierrors.CodeMFAVerificationFailed)
	}
	wa, err := wmfa.NewWebAuthn(s.AuthConfig)
	if err != nil {
		return handlers.AuthFlowResult{}, apierrors.New(
			http.StatusInternalServerError, apierrors.CodeMFAVerificationFailed)
	}
	credential, err := wa.ValidateLogin(wmfa.NewWebAuthnUser(&user, credentials), session, parsed)
	if err != nil || credential.Authenticator.CloneWarning {
		s.recordWebAuthnFailure(logger, user.ID)
		logger.Warn("WebAuthn login verification failed", zap.Error(err))
		return handlers.AuthFlowResult{}, apierrors.New(
			http.StatusUnauthorized, apierrors.CodeMFAVerificationFailed)
	}

	device := byCredentialID[base64.RawURLEncoding.EncodeToString(credential.ID)]
	if device == nil {
		s.recordWebAuthnFailure(logger, user.ID)
		return handlers.AuthFlowResult{}, apierrors.New(
			http.StatusUnauthorized, apierrors.CodeMFAVerificationFailed)
	}
	encrypted, err := wmfa.EncodeWebAuthnCredential(credential, s.AuthConfig.MFAEncryptionKey)
	if err != nil {
		return handlers.AuthFlowResult{}, apierrors.New(
			http.StatusInternalServerError, apierrors.CodeMFAVerificationFailed)
	}
	if err = s.DB.Model(device).Updates(map[string]any{
		"encrypted_secret": encrypted,
		"last_used_at":     time.Now(),
	}).Error; err != nil {
		return handlers.AuthFlowResult{}, apierrors.New(
			http.StatusInternalServerError, apierrors.CodeMFAVerificationFailed)
	}
	if err = cache.ResetMFAAttempts(s.Cache, user.ID.String()); err != nil {
		logger.Warn("Failed to reset MFA attempts", zap.Error(err))
	}

	logger.Info("WebAuthn MFA login verification successful",
		zap.String("user_id", user.ID.String()), zap.String("device_id", device.ID.String()))
	return s.completeMFALogin(isSecure, logger, claims, &user)
}

func (s AuthService) recordWebAuthnFailure(logger *zap.Logger, userID uuid.UUID) {
	if err := cache.IncrementMFAAttempts(s.Cache, userID.String()); err != nil {
		logger.Error("Failed to increment MFA attempts", zap.Error(err))
	}
}

func (s AuthService) webAuthnFinishHandler() http.HandlerFunc {
	return handlers.AuthFlowHandler(s.AuthConfig.CookieSecureForce, s.FinishWebAuthnLogin)
}
