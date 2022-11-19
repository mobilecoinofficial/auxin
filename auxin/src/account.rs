//! Holds and manages data for a Signal account
use libsignal_protocol::{KeyPair, PreKeyRecord, PrivateKey, SignedPreKeyRecord};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::{
	collections::HashMap,
	convert::TryInto,
	fs,
	io::{BufReader, BufWriter, Read, Write},
	path::Path,
};
use uuid::Uuid;
use zkgroup::api::profiles::profile_key::ProfileKey as ZkProfileKey;

/// A signal account "password"
///
/// This is used primarily for authorization with the API
///
/// For API Authorization, Signal uses Basic Authorization,
/// with the ACI UUID as username and this "password"
///
/// If the ACI UUID is unavailable, the phone number is used
///
/// For non default devices, the username has `.<device id>` appended
///
/// See for more details
/// https://github.com/signalapp/Signal-Android/blob/v5.33.3/libsignal/service/src/main/java/org/whispersystems/signalservice/internal/push/PushServiceSocket.java#L1794
/// https://github.com/signalapp/Signal-Android/blob/v5.33.3/libsignal/service/src/main/java/org/whispersystems/signalservice/internal/push/PushServiceSocket.java#L2129
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Password(String);
impl Password {
	pub fn new(password: impl Into<String>) -> Self {
		Self(password.into())
	}

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

/// Signal profile key
// A 32-byte 256-bit profile key
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ProfileKey([u8; 32]);
impl ProfileKey {
	/// Generate a profile key
	///
	/// Should only be called once at registration
	fn generate<R: Rng + CryptoRng>(rng: &mut R) -> Self {
		// Signal generates a 32 byte random key at registration
		// https://github.com/signalapp/Signal-Android/blob/v5.33.3/app/src/main/java/org/thoughtcrime/securesms/crypto/ProfileKeyUtil.java#L75
		// https://github.com/signalapp/Signal-Android/blob/v5.33.3/app/src/main/java/org/thoughtcrime/securesms/registration/RegistrationRepository.java#L81
		// Idk crypto, just use ZkProfileKey to be safe. it does weird math or something.
		Self(ZkProfileKey::generate(rng.gen()).bytes)
	}

	fn new(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}

	/// Get the profile key "version"
	pub fn version(&self, uuid: &str) -> String {
		let ver = ZkProfileKey::create(self.0)
			.get_profile_key_version(*Uuid::parse_str(uuid).unwrap().as_bytes());
		// Seems to be internally guaranteed to succeed?
		// This is literally how signal does it.
		let serialized = bincode::serialize(&ver).unwrap();
		String::from_utf8(serialized).unwrap()
	}

	pub fn as_bytes(&self) -> &[u8; 32] {
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

/// Represents a public and private keypair for use with Signal
///
/// This exists instead of `libsignal`s keypair for the sake of convenience
/// and format control.
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
	// TODO(Diana): Make a HashMap, store active one.
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
		self.next_prekey_id = Self::next_id(self.next_signed_id + 100);
	}
}

impl<R> Identity<R> {
	/// Identity UUID
	pub fn uuid(&self) -> &str {
		&self.uuid
	}

	/// Iterator over prekey IDs and prekeys for this identity, in arbitrary order.
	pub fn prekeys(&self) -> impl Iterator<Item = (&u32, &AuxinKeyPair)> {
		self.identity_prekeys.iter()
	}

	/// Identity keypair
	pub fn identity(&self) -> &AuxinKeyPair {
		&self.identity_keys
	}

	/// Signed prekey pair
	pub fn signed_prekey(&self) -> &AuxinKeyPair {
		&self.signed_prekey
	}

	/// Signed prekey ID
	pub fn signed_id(&self) -> u32 {
		self.next_signed_id
	}

	/// Signature of identity private key and signed prekey public key
	pub fn signature(&self) -> &[u8; 64] {
		&self.signature
	}

	/// Current next prekey ID
	pub fn next_prekey_id(&self) -> u32 {
		self.next_prekey_id
	}

	/// Current next signed prekey ID
	pub fn next_signed_id(&self) -> u32 {
		self.next_signed_id
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
			password: Password::generate(&mut rng),
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

	/// Set the ACI uuid.
	/// Should only be called during registration.
	pub fn set_aci(&mut self, aci: impl Into<String>) {
		let _ = self.aci.insert(Identity::new(aci, self.rng.clone()));
	}

	/// Set the PNI uuid.
	/// Should only be called during registration.
	pub fn set_pni(&mut self, pni: impl Into<String>) {
		let _ = self.pni.insert(Identity::new(pni, self.rng.clone()));
	}

	/// Read our SignalAccount from signal-cli
	///
	/// This should be a temporary thing pending the rewrite
	///
	/// Errors if the file/data for our account already exists
	///
	/// `state_dir` is the signal-cli state directory.
	pub fn from_signal_cli(
		state_dir: impl AsRef<Path>,
		phone: impl Into<String>,
		mut rng: R,
	) -> crate::Result<Self> {
		let state_dir = state_dir.as_ref();
		let phone = phone.into();
		let path = state_dir.join("data").join(&phone);
		let file = fs::File::open(&path)?;
		let file = BufReader::new(file);
		let local: LocalIdentityJson = serde_json::from_reader(file)?;
		if local.version != 3 {
			return Err("Unknown Signal-cli Version".into());
		}

		let path = path.with_extension("d");
		let prekeys = path.join("pre-keys");
		let signed_prekeys = path.join("signed-pre-keys");

		let mut identity_prekeys = HashMap::new();
		for f in fs::read_dir(prekeys)? {
			let f = f?;
			let id: u32 = match f.file_name().to_str() {
				Some(i) => i,
				None => return Err("Invalid prekey".into()),
			}
			.parse()?;
			let mut f = BufReader::new(fs::File::open(f.path())?);
			let mut buf = Vec::new();
			f.read_to_end(&mut buf)?;
			let data = PreKeyRecord::deserialize(&buf)?;
			identity_prekeys.insert(
				id,
				AuxinKeyPair {
					public: data.public_key()?.public_key_bytes()?.try_into()?,
					private: data.private_key()?.serialize()[..].try_into()?,
				},
			);
		}

		let (signed_prekey_id, signed_prekey, signature) = {
			let f = match fs::read_dir(signed_prekeys)?.next() {
				Some(f) => f,
				None => return Err("Invalid signed prekey".into()),
			};
			let f = f?;
			let id: u32 = match f.file_name().to_str() {
				Some(i) => i,
				None => return Err("Invalid signed prekey".into()),
			}
			.parse()?;
			let mut f = BufReader::new(fs::File::open(f.path())?);
			let mut buf = Vec::new();
			f.read_to_end(&mut buf)?;
			let data = SignedPreKeyRecord::deserialize(&buf)?;
			(
				id,
				AuxinKeyPair {
					public: data.public_key()?.public_key_bytes()?.try_into()?,
					private: data.private_key()?.serialize()[..].try_into()?,
				},
				data.signature()?[..].try_into()?,
			)
		};

		Ok(Self {
			phone: PhoneNumber::new(phone),
			aci: Some(Identity {
				uuid: local.uuid,
				identity_keys: AuxinKeyPair {
					public: libsignal_protocol::PublicKey::deserialize(&base64::decode(
						local.public_key,
					)?)?
					.public_key_bytes()?
					.try_into()?,
					private: base64::decode(local.private_key)?[..].try_into()?,
				},
				identity_prekeys,
				signed_prekey,
				signed_prekey_id,
				signature,
				next_prekey_id: local.pre_key_id_offset,
				next_signed_id: local.next_signed_pre_key_id,
				rng: rng.clone(),
			}),
			pni: Some(Identity {
				uuid: local.pni,
				identity_keys: AuxinKeyPair {
					public: libsignal_protocol::PublicKey::deserialize(&base64::decode(
						local.pni_public_key,
					)?)?
					.public_key_bytes()?
					.try_into()?,
					private: base64::decode(local.pni_private_key)?[..].try_into()?,
				},
				// TODO(Diana): signal-cli doesn't save these?
				// We don't actually use PNI, *yet*, but needs to be solved.
				identity_prekeys: HashMap::new(),
				signed_prekey: AuxinKeyPair::generate(&mut rng),
				signed_prekey_id: 0,
				signature: [0; 64],
				next_prekey_id: 0,
				next_signed_id: 0,
				rng: rng.clone(),
			}),
			reg_id: local.registration_id as i32,
			profile_key: ProfileKey::new(base64::decode(local.profile_key)?[..].try_into()?),
			password: Password::new(local.password),
			rng,
		})
	}
}

impl<R> SignalAccount<R> {
	/// Write out our SignalAccount as something signal-cli, and AuxinApp, can understand
	///
	/// This should be a temporary thing pending the rewrite
	///
	/// Errors if the file/data for our account already exists
	///
	/// `state_dir` is the signal-cli state directory.
	pub fn to_signal_cli(&self, state_dir: impl AsRef<Path>) -> crate::Result<()> {
		let state_dir = state_dir.as_ref();
		let data = state_dir.join("data");
		fs::create_dir_all(&data)?;		let path = data.join(self.phone.phone());
		let file = fs::File::options()
			.write(true)
			// .create_new(true)
			// TODO(Diana): TESTING ONLY, NOT FINAL
			.create(true)
			.truncate(true)
			.open(&path)?;
		let file = BufWriter::new(file);
		let path = path.with_extension("d");
		let prekeys = path.join("pre-keys");
		let signed_prekeys = path.join("signed-pre-keys");
		fs::create_dir_all(path.join("identities"))?;
		fs::create_dir_all(&prekeys)?;
		fs::create_dir_all(path.join("sessions"))?;
		fs::create_dir_all(&signed_prekeys)?;

		let aci_key = self.aci().identity();
		let pni_key = self.pni().identity();
		let account = LocalIdentityJson::new(
			self.phone.phone().into(),
			self.aci().uuid().into(),
			self.pni().uuid().into(),
			1,
			self.password.password().into(),
			self.registration_id() as _,
			base64::encode(self.profile_key().as_bytes()),
			base64::encode(aci_key.private()),
			base64::encode(
				libsignal_protocol::PublicKey::from_djb_public_key_bytes(aci_key.public())?
					.serialize(),
			),
			base64::encode(pni_key.private()),
			base64::encode(
				libsignal_protocol::PublicKey::from_djb_public_key_bytes(pni_key.public())?
					.serialize(),
			),
			self.aci().next_prekey_id(),
			self.aci().next_signed_id(),
		);
		serde_json::to_writer_pretty(file, &account)?;

		for (id, key) in self.aci().prekeys() {
			let mut f = fs::File::create(prekeys.join(id.to_string()))?;
			let buf = PreKeyRecord::new(
				*id,
				&libsignal_protocol::KeyPair::new(
					libsignal_protocol::PublicKey::from_djb_public_key_bytes(key.public())?,
					libsignal_protocol::PrivateKey::deserialize(key.private())?,
				),
			)
			.serialize()?;
			f.write_all(&buf)?;
		}
		let id = self.aci().signed_id();
		let key = self.aci().signed_prekey();
		let sig = self.aci().signature();
		let mut f = fs::File::create(signed_prekeys.join(id.to_string()))?;
		let buf = libsignal_protocol::SignedPreKeyRecord::new(
			id,
			0,
			&libsignal_protocol::KeyPair::new(
				libsignal_protocol::PublicKey::from_djb_public_key_bytes(key.public())?,
				libsignal_protocol::PrivateKey::deserialize(key.private())?,
			),
			sig,
		)
		.serialize()?;
		f.write_all(&buf)?;
		Ok(())
	}

	/// Random number identifying this install
	pub fn registration_id(&self) -> i32 {
		self.reg_id
	}

	/// Our profile key
	pub fn profile_key(&self) -> &ProfileKey {
		&self.profile_key
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
		let profile_key = Key::from_slice(self.profile_key().as_bytes());
		let cipher = Aes256Gcm::new(profile_key);
		let nonce = Nonce::from_slice(&[0u8; 12]);

		// Signal trims this to 16 bytes?
		let mut x = cipher.encrypt(nonce, &[0u8; 16][..]).unwrap(); //[..16]
		x.truncate(x.len() - 16);
		x
	}

	/// Account Identity
	pub fn aci(&self) -> &Identity<R> {
		self.aci.as_ref().unwrap()
	}

	/// Account Identity
	pub fn pni(&self) -> &Identity<R> {
		self.pni.as_ref().unwrap()
	}

	/// Account phone number
	pub fn phone(&self) -> &str {
		self.phone.phone()
	}

	/// Account "password", base64
	///
	/// Generally only used for the HTTP authorization header
	pub fn password(&self) -> &str {
		self.password.password()
	}
}

type E164 = String;

/// Just to help us writing out to signal-cli's format
///
/// Copied from auxin_cli state.rs
// TODO(Diana): Better handling across the board for this
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalIdentityJson {
	/// 3
	version: u64,

	/// phone number
	username: E164,

	/// ACI
	uuid: String,

	pni: String,

	/// 1
	device_id: u32,

	/// base64
	password: String,

	registration_id: u32,

	/// base64
	profile_key: String,

	/// ACI private
	#[serde(rename = "identityPrivateKey")]
	private_key: String,

	/// ACI public
	#[serde(rename = "identityKey")]
	public_key: String,

	#[serde(rename = "pniIdentityPrivateKey")]
	pni_private_key: String,

	#[serde(rename = "pniIdentityKey")]
	pni_public_key: String,

	/// For ACI
	pre_key_id_offset: u32,
	/// For ACI
	next_signed_pre_key_id: u32,

	// The following keys appear in signal-cli's json, but we ignore them.
	// They are included here for the purposes of writing the file during registration
	// They all seem to currently null unless otherwise noted.
	// Types are guessed.
	/// False
	is_multi_device: bool,
	device_name: Option<String>,
	/// Timestamp, presumed standard
	last_receive_timestamp: Option<u64>,
	registration_lock_pin: Option<String>,
	pin_master_key: Option<String>,
	storage_key: Option<String>,
	storage_manifest_version: Option<String>,
	/// True
	registered: bool,
	group_store: Option<bool>,
	sticker_store: Option<bool>,
	configuration_store: Option<bool>,
}

impl LocalIdentityJson {
	#[must_use]
	#[allow(clippy::too_many_arguments)]
	fn new(
		username: E164,
		uuid: String,
		pni: String,
		device_id: u32,
		password: String,
		registration_id: u32,
		profile_key: String,
		private_key: String,
		public_key: String,
		pni_private_key: String,
		pni_public_key: String,
		pre_key_id_offset: u32,
		next_signed_pre_key_id: u32,
	) -> Self {
		Self {
			version: 3,
			username,
			uuid,
			pni,
			device_id,
			password,
			registration_id,
			profile_key,
			private_key,
			public_key,
			pni_private_key,
			pni_public_key,
			pre_key_id_offset,
			next_signed_pre_key_id,
			is_multi_device: false,
			device_name: None,
			last_receive_timestamp: None,
			registration_lock_pin: None,
			pin_master_key: None,
			storage_key: None,
			storage_manifest_version: None,
			registered: true,
			group_store: None,
			sticker_store: None,
			configuration_store: None,
		}
	}
}
