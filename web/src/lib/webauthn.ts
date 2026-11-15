type WebAuthnOptionsJSON = {
  publicKey: Record<string, any>;
  mediation?: CredentialMediationRequirement;
};

function fromBase64URL(value: string): Uint8Array<ArrayBuffer> {
  const padded = value
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function toBase64URL(value: ArrayBuffer | null): string {
  if (!value) return "";
  const bytes = new Uint8Array(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function normalizeDescriptors(descriptors?: Array<Record<string, any>>) {
  return descriptors?.map((descriptor) => ({
    ...descriptor,
    id: fromBase64URL(descriptor.id as string),
  }));
}

function serializeCredential(credential: PublicKeyCredential) {
  const response = credential.response;
  const base = {
    id: credential.id,
    rawId: toBase64URL(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(),
  };

  if ("attestationObject" in response) {
    const attestation = response as AuthenticatorAttestationResponse;
    return {
      ...base,
      response: {
        clientDataJSON: toBase64URL(attestation.clientDataJSON),
        attestationObject: toBase64URL(attestation.attestationObject),
        authenticatorData: toBase64URL(
          attestation.getAuthenticatorData?.() ?? null,
        ),
        publicKey: toBase64URL(attestation.getPublicKey?.() ?? null),
        publicKeyAlgorithm: attestation.getPublicKeyAlgorithm?.() ?? 0,
        transports: attestation.getTransports?.() ?? [],
      },
    };
  }

  const assertion = response as AuthenticatorAssertionResponse;
  return {
    ...base,
    response: {
      clientDataJSON: toBase64URL(assertion.clientDataJSON),
      authenticatorData: toBase64URL(assertion.authenticatorData),
      signature: toBase64URL(assertion.signature),
      userHandle: toBase64URL(assertion.userHandle),
    },
  };
}

export async function createWebAuthnCredential(options: WebAuthnOptionsJSON) {
  const publicKey = options.publicKey;
  const credential = (await navigator.credentials.create({
    publicKey: {
      ...publicKey,
      challenge: fromBase64URL(publicKey.challenge as string),
      user: {
        ...(publicKey.user as PublicKeyCredentialUserEntity),
        id: fromBase64URL((publicKey.user as Record<string, string>).id),
      },
      excludeCredentials: normalizeDescriptors(
        publicKey.excludeCredentials as Array<Record<string, any>> | undefined,
      ),
    } as unknown as PublicKeyCredentialCreationOptions,
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("WEBAUTHN_CANCELLED");
  return serializeCredential(credential);
}

export async function getWebAuthnCredential(options: WebAuthnOptionsJSON) {
  const publicKey = options.publicKey;
  const credential = (await navigator.credentials.get({
    publicKey: {
      ...publicKey,
      challenge: fromBase64URL(publicKey.challenge as string),
      allowCredentials: normalizeDescriptors(
        publicKey.allowCredentials as Array<Record<string, any>> | undefined,
      ),
    } as PublicKeyCredentialRequestOptions,
    mediation: options.mediation,
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("WEBAUTHN_CANCELLED");
  return serializeCredential(credential);
}
