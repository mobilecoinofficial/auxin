use crate::net::AuxinHttpsConnection;
use auxin_protos::protos::signalservice::AttachmentPointer;
use log::debug;

pub async fn retrieve_attachment<N: AuxinHttpsConnection>(
	cdn_url: &str,
	net: &mut N,
	attachment_pointer: &AttachmentPointer,
) -> crate::Result<()> {
	let download_path = format!("{}/attachments/{}", cdn_url, attachment_pointer.get_cdnId());

	//Make a request with a body that's an empty string.
	let req = http::Request::get(download_path).body(String::default().into_bytes())?;
	let res = net.request(req).await?;
	debug!("{:?}", res);
	Ok(())
}
