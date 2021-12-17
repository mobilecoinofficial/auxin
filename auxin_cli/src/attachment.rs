// Copyright (c) 2021 MobileCoin Inc.
// Copyright (c) 2021 Emily Cultip

use auxin::{
	attachment::download::{retrieve_attachment, AttachmentDecryptError, AttachmentDownloadError},
	net::api_paths::SIGNAL_CDN,
};
use auxin_protos::AttachmentPointer;
use futures::{Future, FutureExt, TryFutureExt};
use std::{io::Write, pin::Pin};
use tokio::time::Duration;

#[derive(Debug)]
pub enum AttachmentPipelineError {
	Download(AttachmentDownloadError),
	Decrypt(AttachmentDecryptError),
	Save(std::io::Error),
	Timeout(tokio::time::error::Elapsed),
	Parse(serde_json::Value, serde_json::Error),
}

impl std::fmt::Display for AttachmentPipelineError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			AttachmentPipelineError::Download(e) => {
				write!(f, "Failed to download attachment: {:?}", e)
			}
			AttachmentPipelineError::Decrypt(e) => write!(f, "Failed to decrypt attachment: {}", e),
			AttachmentPipelineError::Save(e) => {
				write!(f, "Failed to write attachment to file: {:?}", e)
			}
			AttachmentPipelineError::Timeout(e) => write!(
				f,
				"Timeout while attempting to download attachment: {:?}",
				e
			),
			AttachmentPipelineError::Parse(v, e) => write!(
				f,
				"Could not parse json structure {:?} into an AttachmentPointer. Error: {:?}",
				v,
				e
			),
		}
	}
}

impl std::error::Error for AttachmentPipelineError {}

pub type FutureBox<O, E> = Pin<Box<dyn Future<Output = std::result::Result<O, E>> + Send + Unpin>>;

pub type PendingDownload = FutureBox<(), AttachmentPipelineError>;

/// Writes an attachment, returning the path & filename saved if successful.
pub async fn save_attachment(
	attachment_filename: String,
	decrypted: Vec<u8>,
	download_path_name: String,
) -> std::result::Result<(), AttachmentPipelineError> {
	use std::fs;

	let completed_filename = format!("{}/{}", &download_path_name, &attachment_filename);

	//Create the directory if it's not there.
	let download_path = std::path::Path::new(&download_path_name);
	if !download_path.exists() {
		std::fs::create_dir(download_path).map_err(AttachmentPipelineError::Save)?;
	}

	//(Optionally create, and) write our file.
	let mut file = fs::File::create(&completed_filename).map_err(AttachmentPipelineError::Save)?;
	file.write_all(&decrypted)
		.map_err(AttachmentPipelineError::Save)?;
	file.flush().map_err(AttachmentPipelineError::Save)?;

	Ok(())
}

pub fn initiate_attachment_downloads(
	attachments: Vec<AttachmentPointer>,
	download_path_name: String,
	http_client: &crate::net::AuxinHyperConnection,
	timeout: Option<Duration>,
) -> Vec<PendingDownload> {
	// This doesn't seem to be documented anywhere,
	// but cloning an http client clones a *HANDLE*
	// to the HTTP client. i.e. no deep copy,
	// no initiating a new connection.
	//
	// I found this out becauseHyper's HTTP clien
	// internally calls "self.clone()" inside of
	// its "Client::request()"

	let mut result: Vec<PendingDownload> = Vec::default();

	for att in attachments.iter() {
		let download_path_name = download_path_name.clone();
		let first_handle = Box::pin(retrieve_attachment(
			att.clone(),
			http_client.clone(),
			SIGNAL_CDN,
		))
		//Decryption step.
		.map_ok(|downloaded| {
			(
				downloaded.metadata.get_or_generate_filename(),
				downloaded.decrypt(),
			)
		})
		//Flatten results.
		.map(|r| match r {
			Ok((name, decrypt_result)) => match decrypt_result {
				Ok(decrypted) => Ok((name, decrypted)),
				Err(e) => Err(AttachmentPipelineError::Decrypt(e)),
			},
			Err(e) => Err(AttachmentPipelineError::Download(e)),
		})
		//Save step.
		.map_ok(|(name, decrypted)| Box::pin(save_attachment(name, decrypted, download_path_name)))
		.try_flatten();

		let handle: PendingDownload = {
			// Add a timeout if we need one.
			if let Some(timeout_duration) = timeout {
				Box::pin(
					Box::pin(tokio::time::timeout(timeout_duration, first_handle)).map(
						|r| match r {
							Ok(_) => Ok(()),
							Err(e) => Err(AttachmentPipelineError::Timeout(e)),
						},
					),
				)
			} else {
				//Otherwise, the initial future is good to go.
				Box::pin(first_handle)
			}
		};

		result.push(handle);
	}
	result
}
