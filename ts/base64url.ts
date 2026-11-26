export function toBase64url(data: ArrayBuffer | ArrayBufferView): string {
	const bytes =
		data instanceof ArrayBuffer
			? new Uint8Array(data)
			: new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	let binary = '';
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Also reads standard base64 and padded input. */
export function fromBase64url(text: string): ArrayBuffer {
	const b64 = text.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
	const binary = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
	const out = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
	return out.buffer;
}
