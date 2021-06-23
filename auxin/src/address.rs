use std::error::Error;
use std::result::Result;

use libsignal_protocol::ProtocolAddress;
use uuid::Uuid;
use custom_error::custom_error;

/// Phone number (as formatted to the E.164 standard).
/// String should begin with '+', followed by a country code and a regular 10-digit phone number (no delimiters between parts, as in no "-" or " ").
pub type E164 = String;

custom_error!{AuxinAddressBuildError
    NoPhone{addr:AuxinAddress} = "Attempted to build address {addr} into an auxin device address using its phone number, but it has no phone number.",
    NoUuid{addr:AuxinAddress}  = "Attempted to build address {addr} into an auxin device address using its UUID, but it has no UUID.",
}

#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub enum AuxinAddress { 
    Phone(E164),
    Uuid(Uuid),
    Both(E164, Uuid)
}

impl std::fmt::Display for AuxinAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter)
    -> std::fmt::Result {
        match self { 
            AuxinAddress::Phone(p) => write!(f, "(Phone: {}, UUID: None)", p),
            AuxinAddress::Uuid(u) => write!(f, "(Phone: None, UUID: {})", u),
            AuxinAddress::Both(p, u) => write!(f, "(Phone: {}, UUID: {})", p, u),
        }
    }
}

impl AuxinAddress {
    pub fn get_phone_number(&self) -> Option<&E164> {
        match &self {
            AuxinAddress::Phone(p) => Some(p),
            AuxinAddress::Uuid(_) => None,
            AuxinAddress::Both(p, _) => Some(p),
        }
    }
    pub fn get_uuid(&self) -> Option<&Uuid> {
        match &self {
            AuxinAddress::Phone(_) => None,
            AuxinAddress::Uuid(u) => Some(u),
            AuxinAddress::Both(_, u) => Some(u),
        }
    }
}

#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct AuxinDeviceAddress { 
    pub address: AuxinAddress, 
    pub device_id: u32,
}

impl AuxinDeviceAddress {
    /// Generate a protocol address using our phone number (E164) as its "name"
    pub fn phone_protocol_address(&self) -> Result<ProtocolAddress, Box<dyn Error> > {
        let phone_number = self.address.get_phone_number()
            .ok_or(AuxinAddressBuildError::NoPhone { addr: self.address.clone() })?;
        Ok(ProtocolAddress::new(phone_number.clone(), self.device_id))
    }
    /// Generate a protocol address using our uuid, converted to a string, as its "name"
    pub fn uuid_protocol_address(&self) -> Result<ProtocolAddress, Box<dyn Error> > {
        let addr_uuid = self.address.get_uuid()
            .ok_or(AuxinAddressBuildError::NoUuid { addr: self.address.clone() })?;
        Ok(ProtocolAddress::new(addr_uuid.to_string(), self.device_id))
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_protocol_address() {
        let addr = AuxinAddress::Both(String::from("+12345678910"), Uuid::new_v4());
        let dev_addr = AuxinDeviceAddress {
            address: addr, 
            device_id: 123,
        };
        let phone_address = dev_addr.phone_protocol_address().unwrap();
        let uuid_address = dev_addr.uuid_protocol_address().unwrap();

        assert!(dev_addr.address.get_phone_number().unwrap().eq_ignore_ascii_case(phone_address.name()) ); 
        assert_eq!(phone_address.device_id(), dev_addr.device_id); 
        assert!(uuid_address.name().eq_ignore_ascii_case( &dev_addr.address.get_uuid().unwrap().to_string() )); 
        assert_eq!(uuid_address.device_id(), dev_addr.device_id);
    }
}