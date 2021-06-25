use std::convert::TryFrom;
use std::error::Error;
use std::result::Result;
use std::str::FromStr;

use libsignal_protocol::ProtocolAddress;
use uuid::Uuid;
use custom_error::custom_error;
use serde::{Serialize, Deserialize};

/// Phone number (as formatted to the E.164 standard).
/// String should begin with '+', followed by a country code and a regular 10-digit phone number (no delimiters between parts, as in no "-" or " ").
pub type E164 = String;

custom_error!{AddressError
    NoPhone{addr:AuxinAddress} = "Attempted to build address {addr} into an auxin device address using its phone number, but it has no phone number.",
    NoUuid{addr:AuxinAddress}  = "Attempted to build address {addr} into an auxin device address using its UUID, but it has no UUID.",
    NoDevice{val: String} = "Could not convert {val} into an AuxinDeviceAddress: must end in '.[DeviceId]' where [DeviceID] is a valid integer 0..(2^32-1)",
}

#[derive(Debug, Clone, PartialEq, PartialOrd, Serialize, Deserialize, Hash)]
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

pub const DEFAULT_DEVICE_ID : u32 = 1;

#[derive(Debug, Clone, PartialEq, PartialOrd, Serialize, Deserialize, Hash)]
pub struct AuxinDeviceAddress { 
    pub address: AuxinAddress, 
    pub device_id: u32,
}

impl AuxinDeviceAddress {
    /// Generate a protocol address using our phone number (E164) as its "name"
    pub fn phone_protocol_address(&self) -> Result<ProtocolAddress, Box<dyn Error> > {
        let phone_number = self.address.get_phone_number()
            .ok_or(AddressError::NoPhone { addr: self.address.clone() })?;
        Ok(ProtocolAddress::new(phone_number.clone(), self.device_id))
    }
    /// Generate a protocol address using our uuid, converted to a string, as its "name"
    pub fn uuid_protocol_address(&self) -> Result<ProtocolAddress, Box<dyn Error> > {
        let addr_uuid = self.address.get_uuid()
            .ok_or(AddressError::NoUuid { addr: self.address.clone() })?;
        Ok(ProtocolAddress::new(addr_uuid.to_string(), self.device_id))
    }

    pub fn new_default_device(address: AuxinAddress) -> Self { 
        AuxinDeviceAddress{address, device_id: DEFAULT_DEVICE_ID}
    }
}

impl From<AuxinAddress> for AuxinDeviceAddress {
    fn from(address: AuxinAddress) -> Self {
        Self::new_default_device(address)
    }
}

impl From<AuxinDeviceAddress> for AuxinAddress {
    fn from(device_address: AuxinDeviceAddress) -> Self {
        device_address.address
    }
}

impl TryFrom<&str> for AuxinAddress {
    type Error = Box<dyn Error>;
    fn try_from(val: &str) -> Result<Self, Self::Error> {
        if val.starts_with("+") {
            //Is a phone number. 
            Ok(Self::Phone(val.to_string()))
        }
        else {
            //Should be a UUID
            Ok(Self::Uuid(Uuid::from_str(val)?)) 
        }
    }
}

impl FromStr for AuxinAddress {
    type Err = Box<dyn Error>;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl TryFrom<&str> for AuxinDeviceAddress {
    type Error = Box<dyn Error>;
    fn try_from(val: &str) -> Result<Self, Self::Error> {
        let split = val.rsplit_once(".");
        let (addr, dev) = split.ok_or(Box::new(AddressError::NoDevice{val: val.to_string()}))?;
        let device_id = u32::from_str(dev).map_err(|_e| Box::new(AddressError::NoDevice{val: val.to_string()}))?;
        Ok(AuxinDeviceAddress {
            address: AuxinAddress::try_from(addr)?,
            device_id
        })
    }
}

impl FromStr for AuxinDeviceAddress {
    type Err = Box<dyn Error>;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
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

    #[test]
    fn test_address_from_string() {
        let first_str = "+12345678910";
        let second_str = "2c624fff-b2ae-493a-9ee8-8f99eddaa349";
        let addr1 = AuxinAddress::from_str(first_str).unwrap();
        let addr2 = AuxinAddress::from_str(second_str).unwrap();

        assert_eq!(addr1.get_phone_number().unwrap().as_str(), first_str);
        assert_eq!(addr2.get_uuid().unwrap().to_string().as_str(), second_str);

        //Now with device id
        let first_str_dev = "+12345678910.3";
        let second_str_dev = "2c624fff-b2ae-493a-9ee8-8f99eddaa349.5";

        let dev_addr1 = AuxinDeviceAddress::from_str(first_str_dev).unwrap();
        let dev_addr2 = AuxinDeviceAddress::from_str(second_str_dev).unwrap();

        assert_eq!(dev_addr1.device_id, 3);
        assert_eq!(dev_addr2.device_id, 5);

        assert_eq!(dev_addr1.address, addr1);
        assert_eq!(dev_addr2.address, addr2);
    }
}