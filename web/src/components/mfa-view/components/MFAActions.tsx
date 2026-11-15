import { useTranslation } from "react-i18next";
import { KeyRound, Plus } from "lucide-react";

import { Button } from "@/components/ui/button";

interface MFAActionsProps {
  deviceCount: number;
  maxDevices: number;
  onAddDevice: () => void;
  onAddSecurityKey: () => void;
}

export function MFAActions({
  deviceCount,
  maxDevices,
  onAddDevice,
  onAddSecurityKey,
}: MFAActionsProps) {
  const { t } = useTranslation();

  return (
    <div className="flex items-center gap-2 border-t pt-4">
      <Button
        variant="outline"
        onClick={onAddDevice}
        disabled={deviceCount >= maxDevices}
      >
        <Plus className="mr-2 h-4 w-4" />
        {t("auth.mfa.add_device")}
      </Button>
      <Button
        variant="outline"
        onClick={onAddSecurityKey}
        disabled={deviceCount >= maxDevices}
      >
        <KeyRound className="mr-2 h-4 w-4" />
        {t("auth.mfa.add_security_key")}
      </Button>
    </div>
  );
}
