import { fromBase64url, toBase64url } from './base64url';
import type {
	AuthenticationResponseJSON,
	CreationOptionsJSON,
	CreationPublicKeyJSON,
	CredentialDescriptorJSON,
	RegistrationResponseJSON,
	RequestOptionsJSON,
	RequestPublicKeyJSON,
} from './json';

export { fromBase64url, toBase64url } from './base64url';
export type { RegistrationChallenge } from './generated/RegistrationChallenge';
export type { RegistrationFinish } from './generated/RegistrationFinish';
export type { SignInChallenge } from './generated/SignInChallenge';
export type { SignInFinish } from './generated/SignInFinish';
export type * from './json';

export type Parsers = {
	parseCreationOptionsFromJSON?: (
		json: PublicKeyCredentialCreationOptionsJSON,
	) => PublicKeyCredentialCreationOptions;
	parseRequestOptionsFromJSON?: (
		json: PublicKeyCredentialRequestOptionsJSON,
	) => PublicKeyCredentialRequestOptions;
	isConditionalMediationAvailable?: () => Promise<boolean>;
};

/** What the helpers run against: the browser by default, a stub in tests. */
export type Authenticator = {
	parsers?: Parsers;
	credentials?: Pick<CredentialsContainer, 'create' | 'get'>;
};

const descriptor = (d: CredentialDescriptorJSON): PublicKeyCredentialDescriptor => ({
	type: d.type,
	id: fromBase64url(d.id),
	...(d.transports ? { transports: d.transports as AuthenticatorTransport[] } : {}),
});

export function creationOptions(
	json: CreationPublicKeyJSON,
	parsers: Parsers = {},
): PublicKeyCredentialCreationOptions {
	if (parsers.parseCreationOptionsFromJSON) {
		return parsers.parseCreationOptionsFromJSON(
			json as unknown as PublicKeyCredentialCreationOptionsJSON,
		);
	}
	return {
		...json,
		attestation: json.attestation as AttestationConveyancePreference | undefined,
		authenticatorSelection: json.authenticatorSelection as AuthenticatorSelectionCriteria,
		extensions: json.extensions as AuthenticationExtensionsClientInputs | undefined,
		challenge: fromBase64url(json.challenge),
		user: { ...json.user, id: fromBase64url(json.user.id) },
		excludeCredentials: json.excludeCredentials?.map(descriptor),
	};
}

export function requestOptions(
	json: RequestPublicKeyJSON,
	parsers: Parsers = {},
): PublicKeyCredentialRequestOptions {
	if (parsers.parseRequestOptionsFromJSON) {
		return parsers.parseRequestOptionsFromJSON(
			json as unknown as PublicKeyCredentialRequestOptionsJSON,
		);
	}
	return {
		...json,
		userVerification: json.userVerification as UserVerificationRequirement | undefined,
		extensions: json.extensions as AuthenticationExtensionsClientInputs | undefined,
		challenge: fromBase64url(json.challenge),
		allowCredentials: json.allowCredentials?.map(descriptor),
	};
}

type AnyResponse = AuthenticatorResponse &
	Partial<AuthenticatorAttestationResponse> &
	Partial<AuthenticatorAssertionResponse>;

/** The JSON webauthn-rs reads: the browser's `toJSON()`, or the same built by hand. */
export function credentialJSON(
	credential: PublicKeyCredential,
): RegistrationResponseJSON | AuthenticationResponseJSON {
	if (typeof credential.toJSON === 'function') {
		return credential.toJSON() as RegistrationResponseJSON | AuthenticationResponseJSON;
	}
	const r = credential.response as AnyResponse;
	const response: Record<string, unknown> = { clientDataJSON: toBase64url(r.clientDataJSON) };
	if (r.attestationObject) {
		response.attestationObject = toBase64url(r.attestationObject);
		if (typeof r.getTransports === 'function') response.transports = r.getTransports();
	}
	if (r.authenticatorData) response.authenticatorData = toBase64url(r.authenticatorData);
	if (r.signature) response.signature = toBase64url(r.signature);
	if (r.userHandle !== undefined) {
		response.userHandle = r.userHandle ? toBase64url(r.userHandle) : null;
	}
	return {
		id: credential.id,
		rawId: toBase64url(credential.rawId),
		type: credential.type,
		authenticatorAttachment: credential.authenticatorAttachment ?? null,
		response,
		clientExtensionResults: credential.getClientExtensionResults() as Record<string, unknown>,
	} as RegistrationResponseJSON | AuthenticationResponseJSON;
}

function browser(): Authenticator {
	if (typeof PublicKeyCredential === 'undefined' || typeof navigator === 'undefined') return {};
	return {
		parsers: PublicKeyCredential as unknown as Parsers,
		credentials: navigator.credentials,
	};
}

export function passkeysSupported(env: Authenticator = browser()): boolean {
	return env.credentials !== undefined;
}

/** Whether the browser offers passkeys in the name field's autofill. */
export async function autofillSupported(env: Authenticator = browser()): Promise<boolean> {
	const available = env.parsers?.isConditionalMediationAvailable;
	if (!env.credentials || typeof available !== 'function') return false;
	try {
		return await available.call(env.parsers);
	} catch {
		return false;
	}
}

function need(env: Authenticator): Pick<CredentialsContainer, 'create' | 'get'> {
	if (!env.credentials) throw new Error('This browser cannot use passkeys.');
	return env.credentials;
}

export type CeremonyOptions = { signal?: AbortSignal };

/** Runs the registration ceremony; the answer is the `credential` of `RegistrationFinish`. */
export async function createPasskey(
	options: CreationOptionsJSON,
	{ signal }: CeremonyOptions = {},
	env: Authenticator = browser(),
): Promise<RegistrationResponseJSON> {
	const credential = await need(env).create({
		publicKey: creationOptions(options.publicKey, env.parsers),
		...(signal ? { signal } : {}),
	});
	if (!credential) throw new Error('No passkey was created.');
	return credentialJSON(credential as PublicKeyCredential) as RegistrationResponseJSON;
}

/**
 * Runs a sign-in; the answer is the `credential` of `SignInFinish`. With conditional
 * options it waits for the user to pick a passkey from autofill and answers `null` once
 * `signal` aborts it.
 */
export async function getPasskey(
	options: RequestOptionsJSON,
	{ signal }: CeremonyOptions = {},
	env: Authenticator = browser(),
): Promise<AuthenticationResponseJSON | null> {
	let credential: Credential | null;
	try {
		credential = await need(env).get({
			publicKey: requestOptions(options.publicKey, env.parsers),
			...(options.mediation ? { mediation: options.mediation } : {}),
			...(signal ? { signal } : {}),
		});
	} catch (e) {
		if (signal?.aborted && options.mediation === 'conditional') return null;
		throw e;
	}
	if (!credential) throw new Error('No passkey was chosen.');
	return credentialJSON(credential as PublicKeyCredential) as AuthenticationResponseJSON;
}

export function passkeyError(e: unknown, fallback: string): string {
	if (e instanceof DOMException) {
		if (e.name === 'NotAllowedError') return 'The passkey request was cancelled or timed out.';
		if (e.name === 'InvalidStateError') return 'This device already holds a passkey for you.';
		if (e.name === 'SecurityError') return 'Passkeys do not work at this address.';
		if (e.name === 'AbortError') return 'The passkey request was cancelled.';
	}
	return e instanceof Error && e.message ? e.message : fallback;
}
