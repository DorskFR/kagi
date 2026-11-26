import { describe, expect, it, vi } from 'vitest';
import { fromBase64url, toBase64url } from './base64url';
import {
	type Authenticator,
	autofillSupported,
	type CreationOptionsJSON,
	createPasskey,
	creationOptions,
	getPasskey,
	passkeyError,
	passkeysSupported,
	type RequestOptionsJSON,
	requestOptions,
} from './index';

const creation: CreationOptionsJSON = {
	publicKey: {
		rp: { name: 'kagi', id: 'kagi.example' },
		user: { id: 'c7IcLqms0xfttzM45pplFw', name: 'jeanne', displayName: 'Jeanne' },
		challenge: 'VgFBFOWc0yVBjYbIs0zOph0y1RWjszVWatT_NAQJl88',
		pubKeyCredParams: [
			{ type: 'public-key', alg: -7 },
			{ type: 'public-key', alg: -35 },
			{ type: 'public-key', alg: -257 },
		],
		timeout: 300000,
		excludeCredentials: [
			{ type: 'public-key', id: 'AQEBAQEBAQEBAQEBAQEBAQEBAQE' },
			{ type: 'public-key', id: 'AgI', transports: ['nfc', 'usb'] },
		],
		authenticatorSelection: {
			residentKey: 'preferred',
			requireResidentKey: false,
			userVerification: 'required',
		},
		attestation: 'none',
		extensions: {
			credentialProtectionPolicy: 'userVerificationRequired',
			enforceCredentialProtectionPolicy: false,
			uvm: true,
			credProps: true,
		},
	},
};

const signIn: RequestOptionsJSON = {
	publicKey: {
		challenge: 'en9guE02xY1j7HJMqP5ziprNXlOhDOAPQexzNy19k64',
		timeout: 300000,
		rpId: 'kagi.example',
		allowCredentials: [{ type: 'public-key', id: 'AQEBAQEBAQEBAQEBAQEBAQEBAQE' }],
		userVerification: 'required',
	},
};

const autofill: RequestOptionsJSON = {
	publicKey: {
		challenge: 'g1CIS8D73hOzxBVuwX-NTVRs-SjDNcDvWYC2QqUlAWc',
		timeout: 300000,
		rpId: 'kagi.example',
		allowCredentials: [],
		userVerification: 'required',
		extensions: { uvm: true },
	},
	mediation: 'conditional',
};

const bytes = (buffer: BufferSource | undefined) =>
	buffer instanceof ArrayBuffer ? [...new Uint8Array(buffer)] : undefined;
const raw = (...values: number[]) => new Uint8Array(values).buffer;

function fakeCredential(response: Record<string, unknown>): PublicKeyCredential {
	return {
		id: 'AQI',
		rawId: raw(1, 2),
		type: 'public-key',
		authenticatorAttachment: 'platform',
		response,
		getClientExtensionResults: () => ({ credProps: { rk: true } }),
	} as unknown as PublicKeyCredential;
}

describe('creationOptions', () => {
	it('decodes the binary fields and keeps the rest without native parsing', () => {
		const options = creationOptions(creation.publicKey);
		expect(bytes(options.challenge)).toEqual(bytes(fromBase64url(creation.publicKey.challenge)));
		expect(bytes(options.user.id)).toEqual(bytes(fromBase64url('c7IcLqms0xfttzM45pplFw')));
		expect(options.user.name).toBe('jeanne');
		expect(options.rp).toEqual({ name: 'kagi', id: 'kagi.example' });
		expect(options.pubKeyCredParams.map((p) => p.alg)).toEqual([-7, -35, -257]);
		expect(options.excludeCredentials?.map((d) => bytes(d.id))).toEqual([
			new Array(20).fill(1),
			[2, 2],
		]);
		expect(options.excludeCredentials?.[0]).not.toHaveProperty('transports');
		expect(options.excludeCredentials?.[1]?.transports).toEqual(['nfc', 'usb']);
		expect(options.authenticatorSelection?.residentKey).toBe('preferred');
		expect(options.extensions).toMatchObject({ credProps: true });
		expect(options.timeout).toBe(300000);
	});

	it('hands the JSON to the native parser when there is one', () => {
		const parsed = { challenge: raw(1) } as unknown as PublicKeyCredentialCreationOptions;
		const parseCreationOptionsFromJSON = vi.fn(() => parsed);
		expect(creationOptions(creation.publicKey, { parseCreationOptionsFromJSON })).toBe(parsed);
		expect(parseCreationOptionsFromJSON).toHaveBeenCalledWith(creation.publicKey);
	});
});

describe('requestOptions', () => {
	it('decodes the challenge and the allowed credentials', () => {
		const options = requestOptions(signIn.publicKey);
		expect(bytes(options.challenge)).toEqual(bytes(fromBase64url(signIn.publicKey.challenge)));
		expect(options.allowCredentials?.map((d) => bytes(d.id))).toEqual([new Array(20).fill(1)]);
		expect(options.rpId).toBe('kagi.example');
		expect(options.userVerification).toBe('required');
	});

	it('keeps an empty allow list for usernameless sign-in', () => {
		expect(requestOptions(autofill.publicKey).allowCredentials).toEqual([]);
	});

	it('hands the JSON to the native parser when there is one', () => {
		const parseRequestOptionsFromJSON = vi.fn(
			() => ({ challenge: raw(1) }) as unknown as PublicKeyCredentialRequestOptions,
		);
		requestOptions(signIn.publicKey, { parseRequestOptionsFromJSON });
		expect(parseRequestOptionsFromJSON).toHaveBeenCalledWith(signIn.publicKey);
	});
});

describe('createPasskey', () => {
	it('answers the JSON webauthn-rs reads when the browser has no toJSON', async () => {
		const create = vi.fn(async () =>
			fakeCredential({
				clientDataJSON: raw(123, 125),
				attestationObject: raw(0xa0),
				getTransports: () => ['hybrid', 'internal'],
			}),
		);
		const env: Authenticator = { credentials: { create, get: vi.fn() } };
		const answer = await createPasskey(creation, {}, env);
		expect(answer).toEqual({
			id: 'AQI',
			rawId: 'AQI',
			type: 'public-key',
			authenticatorAttachment: 'platform',
			response: {
				clientDataJSON: toBase64url(raw(123, 125)),
				attestationObject: 'oA',
				transports: ['hybrid', 'internal'],
			},
			clientExtensionResults: { credProps: { rk: true } },
		});
		const call = create.mock.calls[0] as unknown as [CredentialCreationOptions];
		expect(bytes(call[0].publicKey?.challenge)).toEqual(
			bytes(fromBase64url(creation.publicKey.challenge)),
		);
	});

	it('prefers the browser toJSON', async () => {
		const json = { id: 'native' };
		const credential = { ...fakeCredential({}), toJSON: () => json };
		const env: Authenticator = {
			credentials: { create: async () => credential as Credential, get: vi.fn() },
		};
		expect(await createPasskey(creation, {}, env)).toBe(json);
	});

	it('refuses where the browser has no passkeys', async () => {
		expect(passkeysSupported()).toBe(false);
		await expect(createPasskey(creation, {}, {})).rejects.toThrow('cannot use passkeys');
	});
});

describe('getPasskey', () => {
	const assertion = fakeCredential({
		clientDataJSON: raw(1),
		authenticatorData: raw(2),
		signature: raw(3),
		userHandle: raw(4),
	});

	it('runs a modal sign-in and encodes the assertion', async () => {
		const get = vi.fn(async (_: CredentialRequestOptions) => assertion as Credential);
		const answer = await getPasskey(signIn, {}, { credentials: { create: vi.fn(), get } });
		expect(get.mock.calls[0]?.[0]).not.toHaveProperty('mediation');
		expect(answer?.response).toEqual({
			clientDataJSON: 'AQ',
			authenticatorData: 'Ag',
			signature: 'Aw',
			userHandle: 'BA',
		});
	});

	it('asks for conditional mediation and answers null once aborted', async () => {
		const controller = new AbortController();
		const get = vi.fn(
			(request: CredentialRequestOptions) =>
				new Promise<Credential | null>((_, reject) => {
					request.signal?.addEventListener('abort', () =>
						reject(new DOMException('aborted', 'AbortError')),
					);
				}),
		);
		const pending = getPasskey(
			autofill,
			{ signal: controller.signal },
			{ credentials: { create: vi.fn(), get } },
		);
		expect(get.mock.calls[0]?.[0].mediation).toBe('conditional');
		expect(get.mock.calls[0]?.[0].signal).toBe(controller.signal);
		controller.abort();
		expect(await pending).toBeNull();
	});

	it('still throws a modal sign-in that was aborted', async () => {
		const controller = new AbortController();
		controller.abort();
		const get = vi.fn(async () => {
			throw new DOMException('aborted', 'AbortError');
		});
		const env: Authenticator = { credentials: { create: vi.fn(), get } };
		await expect(getPasskey(signIn, { signal: controller.signal }, env)).rejects.toThrow();
	});
});

describe('autofillSupported', () => {
	it('asks the browser when it can', async () => {
		const credentials = { create: vi.fn(), get: vi.fn() };
		const yes = { isConditionalMediationAvailable: async () => true };
		expect(await autofillSupported({ credentials, parsers: yes })).toBe(true);
		const broken = {
			isConditionalMediationAvailable: async () => {
				throw new Error('no');
			},
		};
		expect(await autofillSupported({ credentials, parsers: broken })).toBe(false);
		expect(await autofillSupported({ credentials })).toBe(false);
		expect(await autofillSupported()).toBe(false);
	});
});

describe('passkeyError', () => {
	it('explains the browser errors and falls back', () => {
		expect(passkeyError(new DOMException('x', 'NotAllowedError'), 'f')).toMatch(/cancelled/);
		expect(passkeyError(new DOMException('x', 'InvalidStateError'), 'f')).toMatch(/already/);
		expect(passkeyError(new Error('boom'), 'f')).toBe('boom');
		expect(passkeyError(42, 'fallback')).toBe('fallback');
	});
});
