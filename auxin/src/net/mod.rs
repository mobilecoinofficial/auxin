use libsignal_protocol::SenderCertificate;
use crate::{LocalIdentity, util::Result};
use async_trait::async_trait;

#[async_trait]
pub trait AuxinNetHandler {
    fn retrieve_sender_certificate(&mut self, local_identity: LocalIdentity) -> Result<SenderCertificate>;
    //TODO 
}