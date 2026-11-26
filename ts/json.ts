export type Base64URL = string;

export interface CredentialDescriptorJSON {
	type: 'public-key';
	id: Base64URL;
	transports?: string[];
}

export interface CreationPublicKeyJSON {
	rp: { id?: string; name: string };
	user: { id: Base64URL; name: string; displayName: string };
	challenge: Base64URL;
	pubKeyCredParams: { type: 'public-key'; alg: number }[];
	timeout?: number;
	excludeCredentials?: CredentialDescriptorJSON[];
	authenticatorSelection?: {
		authenticatorAttachment?: string;
		residentKey?: string;
		requireResidentKey?: boolean;
		userVerification?: string;
	};
	attestation?: string;
	attestationFormats?: string[];
	hints?: string[];
	extensions?: Record<string, unknown>;
}

export interface RequestPublicKeyJSON {
	challenge: Base64URL;
	timeout?: number;
	rpId?: string;
	allowCredentials?: CredentialDescriptorJSON[];
	userVerification?: string;
	hints?: string[];
	extensions?: Record<string, unknown>;
}

/** The `options` of a registration start, as webauthn-rs writes them. */
export interface CreationOptionsJSON {
	publicKey: CreationPublicKeyJSON;
}

/** The `options` of a sign-in start; `mediation` is `conditional` for autofill. */
export interface RequestOptionsJSON {
	publicKey: RequestPublicKeyJSON;
	mediation?: CredentialMediationRequirement;
}

export interface RegistrationResponseJSON {
	id: Base64URL;
	rawId: Base64URL;
	type: string;
	authenticatorAttachment?: string | null;
	response: {
		clientDataJSON: Base64URL;
		attestationObject: Base64URL;
		transports?: string[];
	};
	clientExtensionResults: Record<string, unknown>;
}

export interface AuthenticationResponseJSON {
	id: Base64URL;
	rawId: Base64URL;
	type: string;
	authenticatorAttachment?: string | null;
	response: {
		clientDataJSON: Base64URL;
		authenticatorData: Base64URL;
		signature: Base64URL;
		userHandle?: Base64URL | null;
	};
	clientExtensionResults: Record<string, unknown>;
}
