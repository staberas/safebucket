import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { KeyRound } from "lucide-react";

import { MFA_CODE_LENGTH } from "../helpers/constants";
import { MFAVerifyInput } from "./MFAVerifyInput";
import { FormErrorAlert } from "@/components/common/FormErrorAlert";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useRegisterWebAuthnDeviceMutation } from "@/queries/mfa";
import { ProviderType } from "@/types/auth_providers";

interface WebAuthnSetupDialogProps {
  open: boolean;
  onClose: () => void;
  providerType: string;
  hasExistingDevices: boolean;
}

export function WebAuthnSetupDialog({
  open,
  onClose,
  providerType,
  hasExistingDevices,
}: WebAuthnSetupDialogProps) {
  const { t } = useTranslation();
  const mutation = useRegisterWebAuthnDeviceMutation();
  const [name, setName] = useState("Security key");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);

  const needsPassword = providerType !== ProviderType.OIDC;
  const needsCode = providerType === ProviderType.OIDC && hasExistingDevices;

  useEffect(() => {
    if (!open) {
      setName("Security key");
      setPassword("");
      setCode("");
      setError(null);
    }
  }, [open]);

  const register = async () => {
    setError(null);
    try {
      await mutation.mutateAsync({
        name: name.trim(),
        password: needsPassword ? password : undefined,
        code: needsCode ? code : undefined,
      });
      onClose();
    } catch (err) {
      setError(
        err instanceof Error && err.message === "WEBAUTHN_CANCELLED"
          ? t("auth.mfa.security_key_cancelled")
          : t("auth.mfa.security_key_error"),
      );
    }
  };

  const canSubmit =
    name.trim().length > 0 &&
    (!needsPassword || password.length > 0) &&
    (!needsCode || code.length === MFA_CODE_LENGTH) &&
    !mutation.isPending;

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <div className="mb-2 flex h-10 w-10 items-center justify-center rounded-full bg-blue-100">
            <KeyRound className="h-5 w-5 text-blue-600" />
          </div>
          <DialogTitle>{t("auth.mfa.add_security_key_title")}</DialogTitle>
          <DialogDescription>
            {t("auth.mfa.add_security_key_description")}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <FormErrorAlert error={error} />
          <div className="space-y-2">
            <Label htmlFor="security-key-name">
              {t("auth.mfa.device_name_label")}
            </Label>
            <Input
              id="security-key-name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              disabled={mutation.isPending}
            />
          </div>
          {needsPassword && (
            <div className="space-y-2">
              <Label htmlFor="security-key-password">
                {t("auth.password")}
              </Label>
              <Input
                id="security-key-password"
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                disabled={mutation.isPending}
              />
            </div>
          )}
          {needsCode && (
            <div className="space-y-2">
              <Label>{t("auth.mfa.stepup_label")}</Label>
              <MFAVerifyInput
                value={code}
                onChange={setCode}
                disabled={mutation.isPending}
              />
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button onClick={register} disabled={!canSubmit}>
            {mutation.isPending
              ? t("auth.mfa.waiting_for_security_key")
              : t("auth.mfa.add_security_key")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
