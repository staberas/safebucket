import { useTranslation } from "react-i18next";
import { KeyRound, Smartphone, Star } from "lucide-react";
import { hasMultipleDevices } from "../helpers/utils";
import type { IMFADevice } from "@/components/auth-view/types/session";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";

export interface IMFADeviceSelectorProps {
  devices: Array<IMFADevice>;
  selectedDeviceId: string;
  onSelectDevice: (deviceId: string) => void;
  disabled?: boolean;
}

export function MFADeviceSelector({
  devices,
  selectedDeviceId,
  onSelectDevice,
  disabled = false,
}: IMFADeviceSelectorProps) {
  const { t } = useTranslation();

  if (!hasMultipleDevices(devices)) {
    return null;
  }

  return (
    <div className="space-y-2">
      <Label>{t("auth.mfa.select_device")}</Label>
      <div className="grid gap-2 sm:grid-cols-2">
        {devices.map((device) => {
          const selected = device.id === selectedDeviceId;

          return (
            <Button
              key={device.id}
              type="button"
              variant={selected ? "default" : "outline"}
              className="h-auto min-h-10 justify-start py-2 text-left"
              disabled={disabled}
              aria-pressed={selected}
              onClick={() => onSelectDevice(device.id)}
            >
              {device.type === "webauthn" ? (
                <KeyRound className="mr-2 h-4 w-4 shrink-0" />
              ) : (
                <Smartphone className="mr-2 h-4 w-4 shrink-0" />
              )}
              <span className="min-w-0 truncate">{device.name}</span>
              {device.is_default && (
                <Star className="ml-auto h-3 w-3 shrink-0 fill-current" />
              )}
            </Button>
          );
        })}
      </div>
    </div>
  );
}
