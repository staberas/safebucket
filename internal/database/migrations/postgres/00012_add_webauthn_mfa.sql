-- +goose Up
-- +goose StatementBegin

ALTER TYPE mfa_device_type ADD VALUE IF NOT EXISTS 'webauthn';

-- +goose StatementEnd

-- +goose Down
-- PostgreSQL enum values cannot be safely removed while rows may still use them.
