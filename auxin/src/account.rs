//! Holds and manages data for a Signal account
use crate::Result;
use libsignal_protocol::{KeyPair, PrivateKey};
use rand::{CryptoRng, Rng};
use std::collections::HashMap;

/// A signal account "password"
///
/// 18 random bytes, base64 encoded
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Password(String);
impl Password {
	/// Generate a new password
	///
	/// Should only be called once at registration
	pub fn generate<R: Rng + CryptoRng>(rng: &mut R) -> Self {
		// Signal generates a 18 byte random password at registration
		// https://github.com/signalapp/Signal-Android/blob/v5.33.3/app/src/main/java/org/thoughtcrime/securesms/registration/viewmodel/RegistrationViewModel.java#L42
		Self(base64::encode(rng.gen::<[u8; 18]>()))
	}

	/// Base64 encoded password
	pub fn password(&self) -> &str {
		&self.0
	}
}

/// A 32-byte 256-bit profile key
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct ProfileKey([u8; 32]);
impl ProfileKey {
	/// Generate a profile key
	///
	/// Should only be called once at registration
	pub fn generate<R: Rng + CryptoRng>(rng: &mut R) -> Self {
		// Signal generates a 32 byte random key at registration
		// https://github.com/signalapp/Signal-Android/blob/v5.33.3/app/src/main/java/org/thoughtcrime/securesms/crypto/ProfileKeyUtil.java#L75
		// https://github.com/signalapp/Signal-Android/blob/v5.33.3/app/src/main/java/org/thoughtcrime/securesms/registration/RegistrationRepository.java#L81
		Self(rng.gen())
	}

	pub fn key(&self) -> &[u8; 32] {
		&self.0
	}
}

/// E164 formatted phone number
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct PhoneNumber(String);

impl PhoneNumber {
	fn new(phone: impl Into<String>) -> Self {
		Self(phone.into())
	}

	fn phone(&self) -> &str {
		&self.0
	}
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AuxinKeyPair {
	public: [u8; 32],
	private: [u8; 32],
}

impl AuxinKeyPair {
	fn generate<R: Rng + CryptoRng>(rng: &mut R) -> Self {
		let keys = KeyPair::generate(rng);
		// Unwraps should be fine, these methods should never error.
		let public = keys
			.public_key
			.public_key_bytes()
			.unwrap()
			.try_into()
			.unwrap();
		let private = keys.private_key.serialize().try_into().unwrap();
		Self { public, private }
	}

	fn calculate_signature<R: Rng + CryptoRng>(&self, message: &[u8], rng: &mut R) -> [u8; 64] {
		let keypair = PrivateKey::deserialize(self.private()).unwrap();
		keypair.calculate_signature(message, rng).unwrap()[..]
			.try_into()
			.unwrap()
	}

	pub fn public(&self) -> &[u8; 32] {
		&self.public
	}

	pub fn private(&self) -> &[u8; 32] {
		&self.private
	}
}

/// An account or phone number identity, ACI or PNI respectively
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Identity<Rng> {
	/// Identity UUID
	uuid: String,

	/// Identity keys
	identity_keys: AuxinKeyPair,

	/// Prekeys
	identity_prekeys: HashMap<u32, AuxinKeyPair>,

	/// Currently active signed prekey
	signed_prekey: AuxinKeyPair,
	signed_prekey_id: u32,

	/// Signature of identity key and signed prekey
	#[serde(with = "serde_arrays")]
	signature: [u8; 64],

	/// Next prekey ID
	next_prekey_id: u32,

	/// Next signed prekey ID
	next_signed_id: u32,

	#[serde(skip)]
	// #[serde(default = "rand::thread_rng")]
	#[serde(bound = "Rng: rand::Rng")]
	rng: Rng,
}

impl<R: Rng + CryptoRng> Identity<R> {
	fn new(uuid: impl Into<String>, mut rng: R) -> Self {
		// On registration, after getting the ACI/PNI
		// Signal generates an identity keypair for both
		//
		// See
		// https://github.com/signalapp/Signal-Android/blob/v5.33.3/app/src/main/java/org/thoughtcrime/securesms/dependencies/ApplicationDependencyProvider.java#L287-L309
		// and
		// https://github.com/signalapp/Signal-Android/blob/v5.33.3/app/src/main/java/org/thoughtcrime/securesms/registration/RegistrationRepository.java#L131-L140
		let identity_keys = AuxinKeyPair::generate(&mut rng);
		let signed_prekey = AuxinKeyPair::generate(&mut rng);

		// NOTE: Signal-android for some reason generates 2^24-1 bit IDs
		// https://github.com/signalapp/Signal-Android/blob/v5.33.3/app/src/main/java/org/thoughtcrime/securesms/keyvalue/AccountValues.kt#L223-L230
		let signed_prekey_id = rng.gen_range(0, 0xFFFFFF);

		let mut s = Self {
			uuid: uuid.into(),
			signature: {
				let message = signed_prekey.public();
				identity_keys.calculate_signature(message, &mut rng)
			},
			identity_keys,
			identity_prekeys: HashMap::new(),
			signed_prekey,
			signed_prekey_id,

			next_prekey_id: rng.gen_range(0, 0xFFFFFF),
			next_signed_id: Self::next_id(signed_prekey_id),
			rng,
		};
		s.generate_prekeys();
		s
	}

	fn next_id(id: u32) -> u32 {
		(id + 1) % 0xFFFFFF
	}

	fn _next_signed_id(&mut self) -> u32 {
		// From this point on, next signed_prekey ID is as follows
		// (signed_prekey_id + 1) % 0xFFFFFF
		// See
		// https://github.com/signalapp/Signal-Android/blob/v5.33.3/app/src/main/java/org/thoughtcrime/securesms/crypto/PreKeyUtil.java#L76
		self.next_signed_id = Self::next_id(self.next_signed_id);
		self.next_signed_id
	}

	fn _next_prekey_id(&mut self) -> u32 {
		// See https://github.com/signalapp/Signal-Android/blob/v5.33.3/app/src/main/java/org/thoughtcrime/securesms/crypto/PreKeyUtil.java#L46-L63
		self.next_signed_id = Self::next_id(self.next_signed_id + 100);
		self.next_signed_id
	}

	fn next_prekey_offset(&self, i: u32) -> u32 {
		(self.next_prekey_id + i) % 0xFFFFFF
	}

	fn generate_prekeys(&mut self) {
		// On registration, signal generates 100 prekeys
		// See https://github.com/signalapp/Signal-Android/blob/v5.33.3/app/src/main/java/org/thoughtcrime/securesms/crypto/PreKeyUtil.java#L46-L63
		for i in 0..100 {
			self.identity_prekeys.insert(
				self.next_prekey_offset(i),
				AuxinKeyPair::generate(&mut self.rng),
			);
		}
	}
}

impl<R> Identity<R> {
	pub fn uuid(&self) -> &str {
		&self.uuid
	}

	pub fn prekeys(&self) -> impl Iterator<Item = (&u32, &AuxinKeyPair)> {
		self.identity_prekeys.iter()
	}

	pub fn identity(&self) -> &AuxinKeyPair {
		&self.identity_keys
	}

	pub fn signed_prekey(&self) -> &AuxinKeyPair {
		&self.signed_prekey
	}

	pub fn signed_id(&self) -> u32 {
		self.next_signed_id
	}

	pub fn signature(&self) -> &[u8; 64] {
		&self.signature
	}
}

/// Represents the state we are required to keep for our own user account
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SignalAccount<Rng> {
	#[serde(skip)]
	#[serde(bound = "Rng: rand::Rng")]
	rng: Rng,

	/// Phone number
	phone: PhoneNumber,

	/// Account Identity
	aci: Option<Identity<Rng>>,

	/// Phone Number Identity
	pni: Option<Identity<Rng>>,

	/// Registration ID
	reg_id: i32,

	/// Profile Key
	profile_key: ProfileKey,

	/// Randomly generated "password"
	password: Password,
}

impl<R: Rng + CryptoRng + Clone> SignalAccount<R> {
	/// Create a new signal account
	pub fn new(phone: impl Into<String>, mut rng: R) -> Self {
		Self {
			password: dbg!(Password::generate(&mut rng)),
			phone: PhoneNumber::new(phone),
			aci: None,
			pni: None,
			// See https://github.com/signalapp/libsignal-client/blob/6787408e5d8fc8e60c92e43cb0cee3dd6d2c8640/java/shared/java/org/whispersystems/libsignal/util/KeyHelper.java#L41
			// https://github.com/signalapp/Signal-Android/blob/v5.33.3/app/src/main/java/org/thoughtcrime/securesms/registration/RegistrationRepository.java#L68-L75
			reg_id: rng.gen_range(1, 16380),
			// As a new account we won't have an existing profile key, so make one
			profile_key: ProfileKey::generate(&mut rng),
			rng,
		}
	}

	/// Create a new SignalAccount for a newly registered account.
	///
	/// `aci` and `pni` will be from the Signal servers
	pub async fn _register(
		_phone: impl Into<String>,
		_aci: impl Into<String>,
		_pni: impl Into<String>,
		_rng: R,
	) -> Result<Self> {
		todo!()
	}

	pub fn set_aci(&mut self, aci: impl Into<String>) {
		let _ = self.aci.insert(Identity::new(aci, self.rng.clone()));
	}

	pub fn set_pni(&mut self, pni: impl Into<String>) {
		let _ = self.pni.insert(Identity::new(pni, self.rng.clone()));
	}

	pub fn aci(&self) -> &Identity<R> {
		self.aci.as_ref().unwrap()
	}
}

impl<R> SignalAccount<R> {
	pub fn auth_token(&self) -> String {
		// If no ACI, such as during registering, uses the phone number
		// See
		// https://github.com/signalapp/Signal-Android/blob/v5.33.3/libsignal/service/src/main/java/org/whispersystems/signalservice/internal/push/PushServiceSocket.java#L1794
		// https://github.com/signalapp/Signal-Android/blob/v5.33.3/libsignal/service/src/main/java/org/whispersystems/signalservice/internal/push/PushServiceSocket.java#L2129
		match &self.aci {
			Some(aci) => base64::encode(format!("{}:{}", &aci.uuid(), self.password.password())),
			None => base64::encode(format!(
				"{}:{}",
				&self.phone.phone(),
				self.password.password()
			)),
		}
	}

	pub fn registration_id(&self) -> i32 {
		self.reg_id
	}

	pub fn profile_key(&self) -> &[u8] {
		self.profile_key.key()
	}

	/// Unidentified Access key as used by signal
	// during registration only?
	// Groups different?
	pub fn unidentified_access(&self) -> Vec<u8> {
		// See [`auxin::context::get_unidentified_access_for_key`]
		// https://github.com/signalapp/Signal-Android/blob/v5.33.5/app/src/main/java/org/thoughtcrime/securesms/registration/VerifyAccountRepository.kt#L56
		// https://github.com/signalapp/Signal-Android/blob/v5.33.3/libsignal/service/src/main/java/org/whispersystems/signalservice/api/crypto/UnidentifiedAccess.java#L40-L55
		use aes_gcm::{
			aead::{Aead, NewAead},
			Aes256Gcm, Key, Nonce,
		};
		let profile_key = Key::from_slice(self.profile_key());
		let cipher = Aes256Gcm::new(profile_key);
		let nonce = Nonce::from_slice(&[0u8; 12]);

		// Signal trims this to 16 bytes?
		let mut x = cipher.encrypt(nonce, &[0u8; 16][..]).unwrap(); //[..16]
		x.truncate(x.len() - 16);
		x
	}
}
