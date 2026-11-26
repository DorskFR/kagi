import { describe, expect, it } from 'vitest';
import { fromBase64url, toBase64url } from './base64url';

const bytes = (buffer: ArrayBuffer) => [...new Uint8Array(buffer)];

describe('base64url', () => {
	it('round-trips every byte without padding or unsafe characters', () => {
		const all = new Uint8Array(256).map((_, i) => i);
		const text = toBase64url(all);
		expect(text).not.toMatch(/[+/=]/);
		expect(bytes(fromBase64url(text))).toEqual([...all]);
	});

	it('encodes the lengths that need padding in base64', () => {
		expect(toBase64url(new Uint8Array([]))).toBe('');
		expect(toBase64url(new Uint8Array([0xfb]))).toBe('-w');
		expect(toBase64url(new Uint8Array([0xfb, 0xff]))).toBe('-_8');
		expect(toBase64url(new Uint8Array([0xfb, 0xff, 0xbf]))).toBe('-_-_');
	});

	it('reads standard and padded base64 too', () => {
		expect(bytes(fromBase64url('-_8'))).toEqual([0xfb, 0xff]);
		expect(bytes(fromBase64url('+/8='))).toEqual([0xfb, 0xff]);
		expect(bytes(fromBase64url('AQ=='))).toEqual([1]);
	});

	it('encodes a view of a larger buffer, not the whole buffer', () => {
		const buffer = new Uint8Array([9, 1, 2, 3, 9]);
		expect(toBase64url(buffer.subarray(1, 4))).toBe(toBase64url(new Uint8Array([1, 2, 3])));
		expect(toBase64url(new DataView(buffer.buffer, 1, 3))).toBe('AQID');
	});
});
