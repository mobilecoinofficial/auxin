

// NOTE: According to Wikipedia, 
// "PKCS#5 padding is identical to PKCS#7 padding, except that it has only been 
// defined for block ciphers that use a 64-bit (8-byte) block size. In practice
// the two can be used interchangeably."

pub const UNNAMED_ATTACHMENT_PREFIX: &str = "unnamed_attachment_";

pub mod download { 
    use std::convert::TryFrom;

    use auxin_protos::protos::signalservice::AttachmentPointer;
    use log::{debug, warn};
    use aes_gcm::aes::Aes256;
    use block_modes::{BlockMode, Cbc};
    use block_padding::Pkcs7;
    use serde::{Serialize, Deserialize};

    use crate::net::AuxinHttpsConnection;
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

    type AttachmentCipher = Cbc<Aes256, Pkcs7>;

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