# kagi

鍵 — the key. A shared passkey (WebAuthn) relying-party toolkit: a framework-agnostic Rust crate on
[webauthn-rs](https://github.com/kanidm/webauthn-rs) 0.6.2 and a zero-dependency browser helper.
Both ship from this repo and are consumed by git tag:

```toml
kagi = { git = "https://github.com/DorskFR/kagi", tag = "v0.2.0" }
```

```json
"@dorsk/kagi": "github:DorskFR/kagi#v0.2.0"
```

kagi does the WebAuthn ceremonies and the rules around them. It returns verified
`(user, passkey)` results; everything that touches HTTP or sessions stays in the app.

## Rules kagi enforces

- **Relying party from one public URL.** The URL is the only origin and its host the RP id, or
  `Settings::rp_id` when that names a parent domain of the host. Paths, queries, fragments,
  credentials, IP literals and plain http outside `localhost` are refused.
- **Ceremonies** (`CeremonyStore`, in-memory `MemoryCeremonies`):
  - ids are 32 random bytes and only their SHA-256 is stored;
  - each has a purpose (register, sign-in, enrol by grant), is single-use (taken even when the
    finish then fails or names the wrong purpose) and lives 5 minutes;
  - one client address (IPv6 grouped by /64) holds at most 20; more is refused with a retry delay
    and never evicts anyone else's ceremony;
  - 10,000 in total; more is refused (`Error::Busy`), nothing is evicted.
  - with the `serde` feature a `Ceremony` serializes, so apps running several replicas can keep
    ceremonies in a shared store (Postgres, Redis). Such a store follows the same contract: ids
    from `ceremony_id`, only `ceremony_key(id)` kept, `take` removes the row even when it has
    expired, and the limits above (`Limits`, addresses grouped by `network`). The serialized
    form holds the webauthn-rs challenge state: it stays server side.
- **Sign-in:** username-first, usernameless (discoverable) and conditional-UI autofill. After every
  sign-in the counter and backup flags are written back through `CredentialStore::update`. A
  signature counter that does not move forward refuses the sign-in with `Error::Cloned`, apart
  from `Error::Rejected`, so the app can log it as a possibly cloned key.
- **Decoys:** an unknown name and a name without passkeys get the same answer as each other,
  shaped exactly like a real one (same webauthn-rs serializer). Credential ids come from
  webauthn-rs's fake distribution keyed by an app-supplied HMAC key, so they are stable for a name
  across restarts as long as the key is persisted. Transports follow the authenticator the id
  length stands for, as webauthn-rs would have stored them (security keys `["nfc","usb"]`, synced
  and platform passkeys none).
- **Adding a passkey needs a `Proof`:**
  - `Proof::RecentSignIn { at, human }`: `at` is the time of the session's last sign-in
    *assertion* (password or passkey), not when the session was created or rotated, and `human`
    says a person made it. The window defaults to 10 minutes (`Settings::step_up`). Registering a
    passkey returns no new `at`, so it can never extend the window.
  - `Proof::Grant { grant }`: an invite or reset token the app has already verified. This enrols
    identifier + passkey with no password; the grant reference comes back from
    `finish_enrolment`.
  - The ceremony is bound to a `binding` string (session id, grant) checked again at the finish.
- **Account model** (`PasskeyRole`):
  - `Only`: the account has no password; passkeys are the only way in.
  - `Alternative`: passkeys sit next to the password, which keeps working.
  - `ReplacesPassword`: the first passkey turns password sign-in off for good
    (`role.password_sign_in(count)`); `Registered::first` tells the app when that happens.
  - Last-credential guard: the last passkey can only be removed under `Alternative` while the
    account still has a password. `CredentialStore::remove` gets `keep_last` and must check and
    delete atomically.
  - `remove` returns the removed passkey id so the app can end the sessions it opened.
- Stored credentials are webauthn-rs `Passkey` values in its serde format, so existing rows keep
  working.

## What stays in the app

Sessions and cookies, CSRF and `Origin` checks, user tables, HTTP routes, resolving a typed name to
a user, rate limiting (count every `Error::Rejected { name }` and `Error::Cloned { name }`: they
carry the name the sign-in was started for), keeping `SignedIn::at` on the session it opens, ending
sessions when a passkey is removed or when the first passkey replaces the password, storing an
`Enrolment` and consuming its grant in one transaction, and passkey labels and listing.

## Rust

```rust,no_run
use std::net::IpAddr;
use std::time::SystemTime;

use kagi::{
	Account, CredentialStore, Error, Kagi, MemoryCeremonies, PasskeyRole, Proof,
	PublicKeyCredential, RegisterPublicKeyCredential, Settings, Url,
};

fn relying_party(decoy_key: &[u8]) -> Result<Kagi<u64>, Error> {
	let url = Url::parse("https://app.example").expect("a URL");
	Kagi::new(Settings::new(&url, "app", decoy_key), MemoryCeremonies::default())
}

async fn flows<C: CredentialStore<User = u64>>(
	kagi: &Kagi<u64>,
	store: &C,
	address: Option<IpAddr>,
	answer: &PublicKeyCredential,
	created: &RegisterPublicKeyCredential,
	last_sign_in: SystemTime,
) -> Result<(), Error> {
	// Username-first: the app resolves the name; unknown names get a decoy.
	let challenge = kagi.start_sign_in(store, "jeanne", Some(&7), address).await?;
	let signed_in = kagi.finish_sign_in(store, &challenge.ceremony, answer).await?;
	let _ = (signed_in.user, signed_in.passkey, signed_in.at);

	// Autofill on the name field, finished by the same `finish_sign_in`.
	let _autofill = kagi.start_discoverable(address, true).await?;

	// Adding a passkey from a session whose last assertion was at `last_sign_in`.
	let account = Account { user: 7, name: "jeanne", display_name: "Jeanne" };
	let proof = Proof::RecentSignIn { at: last_sign_in, human: true };
	let started = kagi.start_registration(store, account, proof, "session-id", address).await?;
	let registered =
		kagi.finish_registration(store, &started.ceremony, "session-id", created, "Phone").await?;

	// Removing it, then ending the sessions it opened.
	let removed =
		kagi.remove(store, &7, &registered.passkey, PasskeyRole::Alternative, true).await?;
	let _ = removed.passkey;
	Ok(())
}
```

`CredentialStore` is the app's passkey table: `user_handle` (keep the derivation existing passkeys
were registered with, or use `derived_handle`), `passkeys`, `find`, `add`, `update`, `remove`.
Its methods are plain `async fn`s; the futures kagi returns are `Send`.

## Browser

```ts
import { autofillSupported, createPasskey, getPasskey, type SignInChallenge } from '@dorsk/kagi';

const start: SignInChallenge = await (await fetch('/auth/passkey/start', { method: 'POST' })).json();
const credential = await getPasskey(start.options);
await fetch('/auth/passkey/finish', {
	method: 'POST',
	body: JSON.stringify({ ceremony: start.ceremony, credential }),
});

// Autofill: needs `autocomplete="username webauthn"` on the name input.
if (await autofillSupported()) {
	const conditional: SignInChallenge = await (
		await fetch('/auth/passkey/autofill', { method: 'POST' })
	).json();
	const controller = new AbortController();
	const picked = await getPasskey(conditional.options, { signal: controller.signal });
	// `picked` is null once `controller.abort()` hands over to a username-first sign-in.
}
```

The helpers use the browser's `PublicKeyCredential.parse*FromJSON` and `toJSON` when present and
fall back to their own base64url code. `ts/generated` holds the wire types (`RegistrationChallenge`,
`SignInChallenge`, `RegistrationFinish`, `SignInFinish`) generated from the Rust side by ts-rs.

## Development

`make lint` and `make test` (the latter also regenerates `ts/generated`).
