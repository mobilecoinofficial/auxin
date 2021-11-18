// Pulled in from libsignal-service-rs, as both that library and this one are AGPL, at revision 169040fe479e0928e1033d5547ec25e8fccc834c
use aes_gcm::{
	aead::{
		generic_array::{typenum::U32, GenericArray},
		Aead, AeadInPlace,
	},
	Aes256Gcm, NewAead,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use zkgroup::profiles::ProfileKey;

#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ProfileName<S> {
	pub given_name: S,
	pub family_name: Option<S>,
}

impl<S: AsRef<str>> ProfileName<S> {
	pub fn as_ref(&self) -> ProfileName<&str> {
		ProfileName {
			given_name: self.given_name.as_ref(),
			family_name: self.family_name.as_ref().map(|x| x.as_ref()),
		}
	}

	pub fn serialize(&self) -> Vec<u8> {
		if let Some(family_name) = self.family_name.as_ref() {
			self.given_name
				.as_ref()
				.as_bytes()
				.iter()
				.chain(std::iter::once(&0u8))
				.chain(family_name.as_ref().as_bytes())
				.copied()
				.collect()
		} else {
			self.given_name.as_ref().as_bytes().into()
		}
	}

	pub fn is_empty(&self) -> bool {
		self.given_name.as_ref() == "" && self.family_name.is_none()
	}
}

impl ProfileName<String> {
	/// Copying deserialization of a ProfileName.
	pub fn deserialize(data: &[u8]) -> Result<Option<Self>, std::str::Utf8Error> {
		let parts: Vec<&[u8]> = data.split(|x| *x == 0).collect();
		match parts.len() {
			0 => Ok(None),
			1 => Ok(Some(Self {
				given_name: std::str::from_utf8(parts[0])?.to_string(),
				family_name: None,
			})),
			_ => Ok(Some(Self {
				given_name: std::str::from_utf8(parts[0])?.to_string(),
				family_name: Some(std::str::from_utf8(parts[1])?.to_string()),
			})),
		}
	}
}

impl<'de> ProfileName<&'de str> {
	pub fn empty() -> Self {
		ProfileName {
			given_name: "",
			family_name: None,
		}
	}

	/// Zero-copy deserialization of a ProfileName.
	pub fn deserialize<'inp: 'de>(data: &'inp [u8]) -> Result<Option<Self>, std::str::Utf8Error> {
		let parts: Vec<&[u8]> = data.split(|x| *x == 0).collect();
		match parts.len() {
			0 => Ok(None),
			1 => Ok(Some(Self {
				given_name: std::str::from_utf8(parts[0])?,
				family_name: None,
			})),
			_ => Ok(Some(Self {
				given_name: std::str::from_utf8(parts[0])?,
				family_name: Some(std::str::from_utf8(parts[1])?),
			})),
		}
	}
}

/// Encrypt and decrypt a [`ProfileName`] and other profile information.
///
/// # Example
///
/// ```rust
/// # use auxin::{profile_cipher::ProfileName, profile_cipher::ProfileCipher};
/// # use zkgroup::profiles::ProfileKey;
/// # use rand::Rng;
/// # let mut rng = rand::thread_rng();
/// # let some_randomness = rng.gen();
/// let profile_key = ProfileKey::generate(some_randomness);
/// let name = ProfileName::<&str> {
///     given_name: "Bill",
///     family_name: None,
/// };
/// let cipher = ProfileCipher::from(profile_key);
/// let encrypted = cipher.encrypt_name(&name).unwrap();
/// let decrypted = cipher.decrypt_name(&encrypted).unwrap().unwrap();
/// assert_eq!(decrypted.as_ref(), name);
/// ```
pub struct ProfileCipher {
	profile_key: ProfileKey,
}

impl From<ProfileKey> for ProfileCipher {
	fn from(profile_key: ProfileKey) -> Self {
		ProfileCipher { profile_key }
	}
}

const NAME_PADDED_LENGTH_1: usize = 53;
const NAME_PADDED_LENGTH_2: usize = 257;
const NAME_PADDING_BRACKETS: &[usize] = &[NAME_PADDED_LENGTH_1, NAME_PADDED_LENGTH_2];

const ABOUT_PADDED_LENGTH_1: usize = 128;
const ABOUT_PADDED_LENGTH_2: usize = 254;
const ABOUT_PADDED_LENGTH_3: usize = 512;
const ABOUT_PADDING_BRACKETS: &[usize] = &[
	ABOUT_PADDED_LENGTH_1,
	ABOUT_PADDED_LENGTH_2,
	ABOUT_PADDED_LENGTH_3,
];

const EMOJI_PADDED_LENGTH: usize = 32;

const ENCRYPTION_OVERHEAD: usize = 28;
const PAYMENTS_ADDRESS_BASE64_FIELD_SIZE: usize = 776;
pub const PAYMENTS_ADDRESS_CONTENT_SIZE: usize =
	PAYMENTS_ADDRESS_BASE64_FIELD_SIZE * 6 / 8 - ENCRYPTION_OVERHEAD;

#[derive(thiserror::Error, Debug)]
pub enum ProfileCipherError {
	#[error("Encryption error")]
	EncryptionError,
	#[error("UTF-8 decode error {0}")]
	Utf8Error(#[from] std::str::Utf8Error),
	#[error("Input name too long")]
	InputTooLong,
}

fn pad_plaintext(bytes: &mut Vec<u8>, brackets: &[usize]) -> Result<usize, ProfileCipherError> {
	let len = brackets
		.iter()
		.find(|x| **x >= bytes.len())
		.ok_or(ProfileCipherError::InputTooLong)?;
	let len: usize = *len;

	bytes.resize(len, 0);
	assert!(brackets.contains(&bytes.len()));

	Ok(len)
}

impl ProfileCipher {
	pub fn into_inner(self) -> ProfileKey {
		self.profile_key
	}

	fn get_key(&self) -> GenericArray<u8, U32> {
		GenericArray::from(self.profile_key.get_bytes())
	}

	pub fn pad_and_encrypt(
		&self,
		mut bytes: Vec<u8>,
		padding_brackets: &[usize],
	) -> Result<Vec<u8>, ProfileCipherError> {
		let _len = pad_plaintext(&mut bytes, padding_brackets)?;

		let cipher = Aes256Gcm::new(&self.get_key());
		let nonce: [u8; 12] = rand::thread_rng().gen();
		let nonce = GenericArray::from_slice(&nonce);

		cipher
			.encrypt_in_place(nonce, b"", &mut bytes)
			.map_err(|_| ProfileCipherError::EncryptionError)?;

		let mut concat = Vec::with_capacity(nonce.len() + bytes.len());
		concat.extend_from_slice(nonce);
		concat.extend_from_slice(&bytes);
		Ok(concat)
	}

	// Prepends the ;ength of the plaintext (pre-padding) to the buffer
	// before encrypting it normally.
	// Intended to match the behavior of Java's ProfileCipher::encryptWithLength().
	// Provieded padding brackets should not include the cipher's 28 byte encryption overhead.
	pub fn pad_and_encrypt_with_length(
		&self,
		bytes: &Vec<u8>,
		padding_brackets: &[usize],
	) -> Result<Vec<u8>, ProfileCipherError> {
		let length_tag = (bytes.len() as i32).to_le_bytes();
		// length_tag.len() will always be 4 because it is an i32
		let mut new_bytes = Vec::with_capacity(4 + bytes.len());
		new_bytes[0..4].copy_from_slice(&length_tag);
		new_bytes[4..].copy_from_slice(&bytes);

		self.pad_and_encrypt(new_bytes, padding_brackets)
	}

	fn decrypt_and_unpad(&self, bytes: Vec<u8>) -> Result<Vec<u8>, ProfileCipherError> {
		let nonce = GenericArray::from_slice(&bytes[0..12]);
		let cipher = Aes256Gcm::new(&self.get_key());

		let mut plaintext = cipher
			.decrypt(nonce, &bytes[12..])
			.map_err(|_| ProfileCipherError::EncryptionError)?;

		// Unpad
		let len = plaintext
			.iter()
			// Search the first non-0 char...
			.rposition(|x| *x != 0)
			// ...and strip until right after.
			.map(|x| x + 1)
			// If it's all zeroes, the string is 0-length.
			.unwrap_or(0);
		plaintext.truncate(len);
		Ok(plaintext)
	}

	pub fn encrypt_name<'inp>(
		&self,
		name: impl std::borrow::Borrow<ProfileName<&'inp str>>,
	) -> Result<Vec<u8>, ProfileCipherError> {
		let name = name.borrow();
		let bytes = name.serialize();
		self.pad_and_encrypt(bytes, NAME_PADDING_BRACKETS)
	}

	pub fn decrypt_name(
		&self,
		bytes: impl AsRef<[u8]>,
	) -> Result<Option<ProfileName<String>>, ProfileCipherError> {
		let bytes = bytes.as_ref();

		let plaintext = self.decrypt_and_unpad(bytes.into())?;

		Ok(ProfileName::<String>::deserialize(&plaintext)?)
	}

	pub fn encrypt_about(&self, about: String) -> Result<Vec<u8>, ProfileCipherError> {
		let bytes = about.into_bytes();
		self.pad_and_encrypt(bytes, ABOUT_PADDING_BRACKETS)
	}

	pub fn decrypt_about(&self, bytes: impl AsRef<[u8]>) -> Result<String, ProfileCipherError> {
		let bytes = bytes.as_ref();

		let plaintext = self.decrypt_and_unpad(bytes.into())?;

		// XXX This re-allocates.
		Ok(std::str::from_utf8(&plaintext)?.into())
	}

	pub fn encrypt_emoji(&self, emoji: String) -> Result<Vec<u8>, ProfileCipherError> {
		let bytes = emoji.into_bytes();
		self.pad_and_encrypt(bytes, &[EMOJI_PADDED_LENGTH])
	}

	pub fn decrypt_emoji(&self, bytes: impl AsRef<[u8]>) -> Result<String, ProfileCipherError> {
		let bytes = bytes.as_ref();

		let plaintext = self.decrypt_and_unpad(bytes.into())?;

		// XXX This re-allocates.
		Ok(std::str::from_utf8(&plaintext)?.into())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use rand::Rng;
	use zkgroup::profiles::ProfileKey;

	#[test]
	fn roundtrip_name_cipher() {
		let names = [
			"Me and my guitar",                                            // shorter that 53
			"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz",        // one shorter than 53
			"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzx",       // exactly 53
			"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzxf",      // one more than 53
			"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzxfoobar", // a bit more than 53
		];

		// Test the test cases
		assert_eq!(names[1].len(), NAME_PADDED_LENGTH_1 - 1);
		assert_eq!(names[2].len(), NAME_PADDED_LENGTH_1);
		assert_eq!(names[3].len(), NAME_PADDED_LENGTH_1 + 1);

		let mut rng = rand::thread_rng();
		let some_randomness = rng.gen();
		let profile_key = ProfileKey::generate(some_randomness);
		let cipher = ProfileCipher::from(profile_key);
		for name in &names {
			let profile_name = ProfileName::<&str> {
				given_name: name,
				family_name: None,
			};
			assert_eq!(profile_name.serialize().len(), name.len());
			let encrypted = cipher.encrypt_name(&profile_name).unwrap();
			let decrypted = cipher.decrypt_name(&encrypted).unwrap().unwrap();

			assert_eq!(decrypted.as_ref(), profile_name);
			assert_eq!(decrypted.serialize(), profile_name.serialize());
			assert_eq!(&decrypted.given_name, name);
		}
	}

	#[test]
	fn roundtrip_about() {
		let abouts = [
			"Me and my guitar", // shorter that 53
		];

		let mut rng = rand::thread_rng();
		let some_randomness = rng.gen();
		let profile_key = ProfileKey::generate(some_randomness);
		let cipher = ProfileCipher::from(profile_key);

		for &about in &abouts {
			let encrypted = cipher.encrypt_about(about.into()).unwrap();
			let decrypted = cipher.decrypt_about(&encrypted).unwrap();

			assert_eq!(decrypted, about);
		}
	}

	#[test]
	fn roundtrip_emoji() {
		let emojii = ["❤️", "💩", "🤣", "😲", "🐠"];

		let mut rng = rand::thread_rng();
		let some_randomness = rng.gen();
		let profile_key = ProfileKey::generate(some_randomness);
		let cipher = ProfileCipher::from(profile_key);

		for &emoji in &emojii {
			let encrypted = cipher.encrypt_emoji(emoji.into()).unwrap();
			let decrypted = cipher.decrypt_emoji(&encrypted).unwrap();

			assert_eq!(decrypted, emoji);
		}
	}

	#[test]
	fn roundtrip_name() {
		let names = [
			("foo", Some("bar")),
			("foo", None),
			("", None),
			("", Some("bar")),
		];

		for &(given_name, family_name) in &names {
			let uut_name = ProfileName::<&str> {
				given_name,
				family_name,
			};
			let ser = uut_name.serialize();
			let deserialized = ProfileName::<&str>::deserialize(&ser).expect("utf8");
			assert_eq!(Some(uut_name), deserialized);
		}
	}
}
