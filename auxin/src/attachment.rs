use aes_gcm::aes::Aes256;
use block_modes::Cbc;
use block_padding::Pkcs7;
use serde;

// NOTE: According to Wikipedia, 
// "PKCS#5 padding is identical to PKCS#7 padding, except that it has only been 
// defined for block ciphers that use a 64-bit (8-byte) block size. In practice
// the two can be used interchangeably."

pub const UNNAMED_ATTACHMENT_PREFIX: &str = "unnamed_attachment_";

pub const ATTACHMENT_UPLOAD_START_PATH: &str = "https://textsecure-service.whispersystems.org/v2/attachments/form/upload";

type AttachmentCipher = Cbc<Aes256, Pkcs7>;

pub mod download { 
    use super::AttachmentCipher;

    use std::convert::TryFrom;

    use auxin_protos::protos::signalservice::AttachmentPointer;
    use log::{debug, warn};
    use serde::{Serialize, Deserialize};

    use crate::net::AuxinHttpsConnection;

    use block_modes::BlockMode;
    //use ring::hmac::{self, HMAC_SHA256};
        
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum AttachmentIdentifier { 
        CdnId(u64),
        CdnKey(String),
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AttachmentMetadata { 
        pub attachment_identifier: AttachmentIdentifier,
        pub content_type: Option<String>,
        pub key: Vec<u8>,
        pub size: u32,
        pub thumbnail: Option<Vec<u8>>,
        pub digest: Vec<u8>,
        pub file_name: Option<String>,
        /// Bitflags corresponding to VOICE_MESSAGE = 1; BORDERLESS = 2; GIF = 4;
        pub flags: Option<u32>,
        pub width: Option<u32>,
        pub height: Option<u32>,
        pub caption: Option<String>,
        pub blur_hash: Option<String>,
        pub upload_timestamp: Option<u64>,
        pub cdn_number: Option<u32>,
        pub download_start_timestamp: Option<u64>,
        pub download_done_timestamp: Option<u64>,
    }

    impl AttachmentMetadata { 
        pub fn get_or_generate_filename(&self) -> String { 
            match &self.file_name { 
                Some(name) => sanitize_filename::sanitize(name.clone()),
                None => {
                    let timestamp = match self.upload_timestamp { 
                        Some(t) => t,
                        None => {
                            match self.upload_timestamp { 
                                Some(upload_time) => upload_time,
                                None => crate::generate_timestamp()
                            }
                        },
                    };

                    let file_ext = match &self.content_type { 
                        None => String::default(),
                        Some(ty) => {
                            sanitize_filename::sanitize(
                                if ty.contains("/") {
                                    // 1 here will always be the second element i.e. after the / 
                                    ty.split_once("/").unwrap().1.to_string().to_ascii_lowercase()
                                }
                                else { 
                                    ty.to_ascii_lowercase()
                            })
                        }
                    };
                    
                    format!("{}{}{}", super::UNNAMED_ATTACHMENT_PREFIX, timestamp, file_ext)
                },
            }
        } 
    }

    #[derive(Debug, Clone)]
    pub enum AttachmentMetaError { 
        NoIdent,
        NoKey(AttachmentIdentifier),
        NoDigest(AttachmentIdentifier),
        NoSize(AttachmentIdentifier),
    }

    impl std::fmt::Display for AttachmentMetaError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self { 
                AttachmentMetaError::NoIdent => write!(f, "Attempted to decode an attachment pointer with no CDN ID and no CDN Key. There is no identifier with which to retrieve the attachment."),
                AttachmentMetaError::NoKey(id) => write!(f, "Attempted to decode an attachment pointer (identifier {:?}) which has no key, and wouldn't be possible to decrypt.", id),
                AttachmentMetaError::NoDigest(id) => write!(f, "Attempted to decode an attachment pointer (identifier {:?}) which has no digest, and wouldn't be possible to decrypt.", id),
                AttachmentMetaError::NoSize(id) => write!(f, "Attempted to decode an attachment pointer (identifier {:?}) which has no size, and wouldn't be possible to deserialize.", id),
            }
        }
    }

    impl std::error::Error for AttachmentMetaError {}

    pub struct EncryptedAttachment {
        pub metadata: AttachmentMetadata,
        pub ciphertext: Vec<u8>, 
    }

    impl TryFrom<&AttachmentPointer> for AttachmentMetadata {
        type Error = AttachmentMetaError;

        fn try_from(value: &AttachmentPointer) -> Result<Self, Self::Error> {
            let attachment_ident = {
                if value.has_cdnId() { 
                    AttachmentIdentifier::CdnId(value.get_cdnId())
                }
                else if value.has_cdnKey() { 
                    AttachmentIdentifier::CdnKey(value.get_cdnKey().to_string())
                }
                else { 
                    return Err(AttachmentMetaError::NoIdent);
                }
            };

            let key = { 
                if value.has_key() { 
                    value.get_key().to_vec()
                }
                else { 
                    return Err(AttachmentMetaError::NoKey(attachment_ident.clone()));
                }
            };

            let digest = { 
                if value.has_digest() { 
                    value.get_digest().to_vec()
                }
                else { 
                    return Err(AttachmentMetaError::NoDigest(attachment_ident.clone()));
                }
            };
            let size = { 
                if value.has_size() { 
                    value.get_size()
                }
                else { 
                    return Err(AttachmentMetaError::NoSize(attachment_ident.clone()));
                }
            };

            //All of the mandatory fields have been filled.
            let mut result = AttachmentMetadata { 
                attachment_identifier: attachment_ident,
                content_type: None, key, size, thumbnail: None, digest, 
                file_name: None, flags: None, width: None, height: None, caption: None,
                blur_hash: None, upload_timestamp: None, cdn_number: None,
                download_start_timestamp: None, download_done_timestamp: None,
            };

            if value.has_contentType() { 
                result.content_type = Some(value.get_contentType().to_string());
            }
            if value.has_thumbnail() { 
                result.thumbnail = Some(value.get_thumbnail().to_vec()); 
            }
            if value.has_fileName() { 
                result.file_name = Some(value.get_fileName().to_string());
            }
            if value.has_flags() { 
                result.flags = Some(value.get_flags());
            }
            if value.has_width() { 
                result.width = Some(value.get_width());
            }
            if value.has_height() { 
                result.width = Some(value.get_height());
            }
            if value.has_caption() { 
                result.caption = Some(value.get_caption().to_string());
            }
            if value.has_blurHash() { 
                result.blur_hash = Some(value.get_blurHash().to_string());
            }
            if value.has_uploadTimestamp() { 
                result.upload_timestamp = Some(value.get_uploadTimestamp());
            }
            if value.has_cdnNumber() { 
                result.cdn_number = Some(value.get_cdnNumber());
            }

            return Ok(result);
        }
    }

    #[derive(Debug, Clone)]
    pub enum AttachmentDecryptError { 
        TooSmall(String, usize, usize),
        CantVerifyMac(String, Box<ring::error::Unspecified>),
        CantConstructCipher(String, String),
        DecryptionErr(String, String),
    }

    impl std::fmt::Display for AttachmentDecryptError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self { 
                AttachmentDecryptError::TooSmall(name, minimum, actual) => write!(f, "Cannot decrypt an attachment with name {}: The cryptographic overhead is {} bytes but the actual size of this attachment is {}", name, minimum, actual),
                AttachmentDecryptError::CantVerifyMac(name, e) => write!(f, "Could not verify HMAC-SHA256 of attachment with name {} due to the following error: {:?}", name, e),
                AttachmentDecryptError::CantConstructCipher(filename, error_text) => write!(f, "Could not construct a cipher for attachment with name {} due to the following error: {}", filename, error_text),
                AttachmentDecryptError::DecryptionErr(filename, error_text) => write!(f, "Could not decrypt attachment with name {} due to the following error: {}", filename, error_text),
            }
        }
    }

    impl std::error::Error for AttachmentDecryptError {}

    impl EncryptedAttachment { 
        pub fn decrypt(&self) -> std::result::Result<Vec<u8>, AttachmentDecryptError> { 
            //After some testing THESE ARE DEFINITELY CORRECT!
            const BLOCK_SIZE: usize = 16;
            const CIPHER_KEY_SIZE: usize = 32; 
            const MAC_KEY_SIZE: usize = 32; 
            // const TAG_SIZE: usize = 16;

            let filename = self.metadata.get_or_generate_filename();

            let minimum_size = BLOCK_SIZE + MAC_KEY_SIZE;
            if self.ciphertext.len() <= minimum_size {
                return Err(AttachmentDecryptError::TooSmall(filename, minimum_size, self.ciphertext.len()))
            }

            //Set up our ciphers.
            //The IV is built-in with the ciphertext here. We beed to split it out so there isn't a weird little 
            let (iv_slice, ciphertext_slice) = self.ciphertext.split_at(BLOCK_SIZE);
            // MAC key lives at the end of the ciphertext. This is required. The Mac Key is not ciphertext. Tested - this is necessary.
            let ciphertext_slice = &ciphertext_slice[0.. ( ciphertext_slice.len() - MAC_KEY_SIZE)];

            let mut cipher_key_bytes: [u8; CIPHER_KEY_SIZE] = [0; CIPHER_KEY_SIZE];
            cipher_key_bytes.copy_from_slice(&self.metadata.key.as_slice()[0..CIPHER_KEY_SIZE]);

            let cipher = AttachmentCipher::new_from_slices(&cipher_key_bytes, &iv_slice)
                .map_err(|e| AttachmentDecryptError::CantConstructCipher(filename.clone(), format!("{:?}", e)))?;

            let decrypted = cipher.decrypt_vec(ciphertext_slice)
                .map_err(|e| AttachmentDecryptError::DecryptionErr(filename.clone(), format!("{:?}", &e)))?;

            //TODO: Verify Mac.
            /*{
                let mut mac_key_bytes: [u8; MAC_KEY_SIZE] = [0; MAC_KEY_SIZE];
                mac_key_bytes.copy_from_slice(&self.metadata.key.as_slice()[CIPHER_KEY_SIZE..(CIPHER_KEY_SIZE+MAC_KEY_SIZE)]);
                let mac_key = hmac::Key::new(hmac::HMAC_SHA256, &mac_key_bytes);
            }*/

            if decrypted.len() < (self.metadata.size as usize) {
                warn!("Received file {}, but the expected size was {} and the actual size was {}", &self.metadata.get_or_generate_filename(), (self.metadata.size as usize), decrypted.len());
            }

            //Snip off trailing padding.
            let mut result = Vec::default();
            result.extend_from_slice(&decrypted[0..(self.metadata.size as usize)]); 

            Ok(result)
        }
    /*
        fn verify_mac(&self) -> std::result::Result<(), AttachmentDecryptError> { 
            /*
            let mut cipher = hmac::Context::with_key(&mac_key);
            
            cipher.update(&self.ciphertext);
            let our_mac = cipher.sign();*/

            //mac_key_bytes
            Ok(())
        }*/
    }


    #[derive(Debug, Clone)]
    pub enum AttachmentDownloadError { 
        Meta(AttachmentMetaError),
        CantBuildRequest(String),
        NetworkError(String),
    }

    impl std::fmt::Display for AttachmentDownloadError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self { 
                AttachmentDownloadError::Meta(m) => write!(f, "Downloading attachment failed because sanity-checks on attachment metadata failed: {:?}", m),
                AttachmentDownloadError::CantBuildRequest(e) => write!(f, "Could not build a request to download an attachment: {}", e),
                AttachmentDownloadError::NetworkError(e) => write!(f, "Could not download an attachment: {}", e),
            }
        }
    }

    impl std::error::Error for AttachmentDownloadError {}

	// This doesn't seem to be documented anywhere, 
	// but cloning an http client clones a *HANDLE*
	// to the HTTP client. i.e. no deep copy,
	// no initiating a new connection.
	// 
	// I found this out becauseHyper's HTTP client 
	// internally calls "self.clone()" inside of 
	// its "Client::request()"

    pub async fn retrieve_attachment<H: AuxinHttpsConnection>(attachment: AttachmentPointer, http_client: H, cdn_address: &str) -> std::result::Result<EncryptedAttachment, AttachmentDownloadError> {
		let meta = AttachmentMetadata::try_from(&attachment).map_err(|e| AttachmentDownloadError::Meta(e))?;
		let download_path = match &meta.attachment_identifier {
			AttachmentIdentifier::CdnId(id) => format!("{}/attachments/{}", cdn_address, id),
			//TODO: Test this second path. I have an intuitive sense I'm missing something here, but I'm not sure why.
			AttachmentIdentifier::CdnKey(key) => format!("{}/attachments/{}", cdn_address, key),
		};

		//Make a request with a body that's an empty string.
		let req = http::Request::get(download_path).body(String::default().into_bytes())
            .map_err(|e| AttachmentDownloadError::CantBuildRequest(format!("{:?}", e)))?;
		let res = http_client.request(req).await
            .map_err(|e| AttachmentDownloadError::NetworkError(format!("{:?}", e)))?;

		let (parts, body) = res.into_parts();

		debug!("Retrieved a {}-byte attachment with the following HTTP headers: {:?}", body.len(), parts);
		debug!("If we were to save this as a file, the filename would be: {}", meta.get_or_generate_filename());
        Ok(EncryptedAttachment {
			metadata: meta,
            ciphertext: body,
		})
    }
}

pub mod upload {
    use log::debug;
    use rand::{CryptoRng, Rng, RngCore};
    use block_modes::BlockMode;
    use ring::hmac::{self};

    use serde::{
        Deserialize, Serialize,
    };

    use crate::net::AuxinHttpsConnection;

    use super::AttachmentCipher;


    #[derive(Debug, Clone)]
    pub enum AttachmentEncryptError { 
        CantConstructCipher(String, String),
    }
    impl std::fmt::Display for AttachmentEncryptError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self { 
                AttachmentEncryptError::CantConstructCipher(filename, error_text) => write!(f, "Could not construct a cipher to encrypt attachment with name {} due to the following error: {}", filename, error_text),
            }
        }
    }
    impl std::error::Error for AttachmentEncryptError {}



    #[derive(Debug, Clone)]
    pub enum AttachmentUploadError { 
        CantConstructRequest(String,String),
        AttachmentIdNetworkErr(String),
    }

    impl std::fmt::Display for AttachmentUploadError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self { 
                AttachmentUploadError::CantConstructRequest(uri, err) => write!(f, "Cannot construct initial request for an attachment ID - tried to make a request to {}, got error: {}", uri, err),
                AttachmentUploadError::AttachmentIdNetworkErr(err) => write!(f, "Initial request for attachment ID errored: {}",err),
            }
        }
    }
    impl std::error::Error for AttachmentUploadError {}

    //fn guess_ciphertext_length(plaintext_length: usize) -> usize { (((plaintext_length / 16) +1) * 16) + 32 }

    fn get_padded_size(initial_size: usize) -> usize {
        std::cmp::max(541, (
            //Do not ask me why this is the math. I'm replicating the math from libsignal-service-java's PaddingInputStream,
            //to stay consistent.
            //This uses Java's Math.log - which appears to be a natural logarithm.
            (
                (initial_size as f64).ln() / 1.05_f64.ln()
            ).ceil()
            .powf(1.05_f64)
        ).floor() as usize)
    }

    #[derive(Clone, Debug)]
    pub struct PreparedAttachment {
        pub attachment_key: [u8;32],
        pub digest_key: [u8;32],
        pub filename: String,
        data: Vec<u8>,
        pub unpadded_size: usize,
    }

    pub fn encrypt_attachment<R: CryptoRng + Rng + RngCore>(filename: &str, attachment: &[u8], rng: &mut R) -> std::result::Result<PreparedAttachment, AttachmentEncryptError> {
        
        let unpadded_size = attachment.len();

        //Set up ciphers and such
        let attachment_key: [u8;32] = rng.gen();
        let digest_key_bytes: [u8;32] = rng.gen();

        let iv: [u8; 16] = rng.gen(); //Initialization vector / nonce.

        let padded_length = get_padded_size(attachment.len());

        //Assert we're not attempting to create a negative amount of padding.  
        assert!( padded_length >= attachment.len());

        let mut padded_plaintext: Vec<u8> = Vec::with_capacity(padded_length);
        padded_plaintext[0..attachment.len()].copy_from_slice(&attachment);

        let mime_type_guess = mime_guess::from_path(filename);
        let mime = mime_type_guess.first_or_octet_stream();
        let mime_name = mime.essence_str();

        debug!("Guessed MIME type {} for {}", mime_name, filename);

        let cipher = AttachmentCipher::new_from_slices(&attachment_key, &iv)
            .map_err(|e| AttachmentEncryptError::CantConstructCipher(filename.to_string(), format!("{:?}", e)))?;

        let digest_key = hmac::Key::new(hmac::HMAC_SHA256, &digest_key_bytes);
        let mut digest: hmac::Context = hmac::Context::with_key(&digest_key);

        //Actually write our data.
        let mut output: Vec<u8> = Vec::default();

        //You start by writing the IV - see line 241 in this file, in decrypt()
        output.extend_from_slice(&iv);
        digest.update(&iv);

        let ciphertext = cipher.encrypt_vec(attachment);
        //Mac is updated from ciphertext, not plaintext.
        output.extend_from_slice(&ciphertext);
        digest.update(&ciphertext);

        let signature = digest.sign();
        //Write the tag after our ciphertext.
        output.extend_from_slice(&signature.as_ref());

        Ok(PreparedAttachment {
            filename: filename.to_string(),
            data: output,
            unpadded_size,
            attachment_key,
            digest_key: digest_key_bytes,
        })
    }


    /// A ticket received in response to a GET request to https://textsecure-service.whispersystems.org/v2/attachments/form/upload
    /// This will include everyting you need to send the cdn an attachment it won't reject. 
    #[derive(Serialize, Deserialize, Debug, Clone, Default)]
    #[serde(rename_all = "camelCase")]
    pub struct PreUploadToken { 
        pub key: String,
        //I got: "<16 capital-alphanumerics>/<date in YYYYMMDD>/us-east-1/s3/aws4_request"
        pub credential: String,
        // "private"
        pub acl: String,
        // "AWS4-HMAC-SHA256"
        pub algorithm: String,
        pub date: String,
        //Still alphanumerics, capital and lowercase.
        pub policy: String,
        //Also alphanumerics, but lowercase-only for me
        pub signature: String,
        pub attachment_id: u64,
        pub attachment_id_string:String,
    }

    // "Reserve an ID for me, I am going to start an upload" with a reply of "Okay, here's your ID," basically.
    /// Ask the server for a set of pre-attachment-upload information that will be used to upload an attachment
    pub async fn request_attachment_token<H: AuxinHttpsConnection>(http_client: H, auth: (&str, &str)) -> std::result::Result<(), AttachmentUploadError> { 
        let req_addr = super::ATTACHMENT_UPLOAD_START_PATH.to_string();

        let request: http::Request<Vec<u8>> = http::request::Request::get(&req_addr)
                            .header(auth.0, auth.1)
                            .header("X-Signal-Agent", crate::net::X_SIGNAL_AGENT)
                            .header("User-Agent", crate::net::USER_AGENT)
                            .body(Vec::default())
                            .map_err(|e| AttachmentUploadError::CantConstructRequest(req_addr.clone(), format!("{:?}", e)))?;
        let response = http_client.request(request).await
            .map_err(|e| AttachmentUploadError::AttachmentIdNetworkErr(format!("{:?}", e)))?;


		let (parts, body) = response.into_parts();

        let body = String::from_utf8_lossy(&body);

        debug!("Received response with headers {:?} and body {}", &parts, &body);
        Ok(())
    }

    pub fn upload_attachment<H: AuxinHttpsConnection>(attachment: PreparedAttachment, http_client: H, cdn_address: &str) {
        let upload_address = format!("{}/attachments/", cdn_address);
    }
}