use std::time::{Duration, SystemTime};

use crate::{Error, Purpose};

const CLOCK_SKEW: Duration = Duration::from_secs(60);

/// What lets a caller add a passkey to an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Proof {
	/// The session's last sign-in assertion (password or passkey) happened at `at`, done by a
	/// person (`human`) rather than a token, proxy header or session refresh. `at` is the time
	/// of that assertion, never when the session was created or last rotated.
	RecentSignIn { at: SystemTime, human: bool },
	/// An invite or reset token the app has already verified. `grant` is the app's reference
	/// to it, handed back by `finish_enrolment` so the app can consume it.
	Grant { grant: String },
}

impl Proof {
	pub(crate) fn purpose(&self, now: SystemTime, window: Duration) -> Result<Purpose, Error> {
		match self {
			Self::Grant { .. } => Ok(Purpose::Enrol),
			Self::RecentSignIn { human: false, .. } => Err(Error::StepUp),
			Self::RecentSignIn { at, human: true } => match now.duration_since(*at) {
				Ok(age) if age <= window => Ok(Purpose::Register),
				Ok(_) => Err(Error::StepUp),
				Err(ahead) if ahead.duration() <= CLOCK_SKEW => Ok(Purpose::Register),
				Err(_) => Err(Error::StepUp),
			},
		}
	}
}

/// What a passkey is to an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyRole {
	/// The account has no password; passkeys are its only way in.
	Only,
	/// Passkeys sit next to the password, which keeps working.
	Alternative,
	/// The first passkey turns password sign-in off for good.
	ReplacesPassword,
}

impl PasskeyRole {
	pub const fn password_sign_in(self, passkeys: usize) -> bool {
		match self {
			Self::Only => false,
			Self::Alternative => true,
			Self::ReplacesPassword => passkeys == 0,
		}
	}

	pub const fn may_remove_last(self, has_password: bool) -> bool {
		match self {
			Self::Only | Self::ReplacesPassword => false,
			Self::Alternative => has_password,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	const WINDOW: Duration = Duration::from_secs(10 * 60);

	fn signed_in(now: SystemTime, ago: i64, human: bool) -> Proof {
		let at = if ago >= 0 {
			now - Duration::from_secs(ago.unsigned_abs())
		} else {
			now + Duration::from_secs(ago.unsigned_abs())
		};
		Proof::RecentSignIn { at, human }
	}

	#[test]
	fn a_recent_sign_in_counts_only_inside_its_window() {
		let now = SystemTime::now();
		let ok = |proof: Proof, window| proof.purpose(now, window);
		assert_eq!(
			ok(signed_in(now, 0, true), WINDOW).unwrap(),
			Purpose::Register
		);
		assert_eq!(
			ok(signed_in(now, 600, true), WINDOW).unwrap(),
			Purpose::Register
		);
		assert!(matches!(
			ok(signed_in(now, 601, true), WINDOW),
			Err(Error::StepUp)
		));
		assert!(matches!(
			ok(signed_in(now, 3600, true), WINDOW),
			Err(Error::StepUp)
		));
		assert!(ok(signed_in(now, 3600, true), Duration::from_secs(7200)).is_ok());
		assert!(matches!(
			ok(signed_in(now, 0, false), WINDOW),
			Err(Error::StepUp)
		));
		assert!(ok(signed_in(now, -30, true), WINDOW).is_ok());
		assert!(matches!(
			ok(signed_in(now, -3600, true), WINDOW),
			Err(Error::StepUp)
		));
	}

	#[test]
	fn a_grant_enrols_without_a_sign_in() {
		let grant = Proof::Grant {
			grant: "invite-1".into(),
		};
		assert_eq!(
			grant.purpose(SystemTime::now(), Duration::ZERO).unwrap(),
			Purpose::Enrol
		);
	}

	#[test]
	fn the_role_decides_password_sign_in_and_the_last_passkey() {
		use PasskeyRole::*;
		assert!(!Only.password_sign_in(0));
		assert!(Alternative.password_sign_in(0) && Alternative.password_sign_in(3));
		assert!(ReplacesPassword.password_sign_in(0));
		assert!(!ReplacesPassword.password_sign_in(1));
		assert!(!Only.may_remove_last(true));
		assert!(!ReplacesPassword.may_remove_last(true));
		assert!(Alternative.may_remove_last(true));
		assert!(!Alternative.may_remove_last(false));
	}
}
