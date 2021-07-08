use std::convert::TryFrom;
use std::error::Error;
use std::str::FromStr;

use libsignal_protocol::ProtocolAddress;
use uuid::Uuid;
use custom_error::custom_error;
use serde::{Serialize, Deserialize};
use crate::Result;

/// Phone number (as formatted to the E.164 standard).
/// String should begin with '+', followed by a country code and a regular 10-digit phone number (no delimiters between parts, as in no "-" or " ").
pub type E164 = String;
// Possibly move to using https://github.com/rustonaut/rust-phonenumber when needed

custom_error!{AddressError
    NoPhone{addr:AuxinAddress} = "Attempted to get a phone number for {addr}, but it has no phone number.",
    NoUuid{addr:AuxinAddress}  = "Attempted to get a UUID for {addr}, but it has no UUID.",
    NoDevice{val: String} = "Could not convert {val} into an AuxinDeviceAddress: must end in '.[DeviceId]' where [DeviceID] is a valid integer 0..(2^32-1)",
}

//NOTE: UUID changes when phone number is re-registered. 
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
    pub fn get_phone_number(&self) -> Result<&E164> {
        match &self {
            AuxinAddress::Phone(p) => Ok(p),
            AuxinAddress::Uuid(_) => Err(Box::new(AddressError::NoPhone{addr: self.clone() })),
            AuxinAddress::Both(p, _) => Ok(p),
        }
    }
    pub fn get_uuid(&self) -> Result<&Uuid> {
        match &self {
            AuxinAddress::Phone(_) => Err(Box::new(AddressError::NoUuid{addr: self.clone() })),
            AuxinAddress::Uuid(u) => Ok(u),
            AuxinAddress::Both(_, u) => Ok(u),
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
    pub fn get_phone_number(&self) -> Result<&E164> {
        self.address.get_phone_number()
    }
    pub fn get_uuid(&self) -> Result<&Uuid> {
        self.address.get_uuid()
    }
    /// Generate a protocol address using our phone number (E164) as its "name"
    pub fn phone_protocol_address(&self) -> Result<ProtocolAddress> {
        let phone_number = self.get_phone_number()?;
        Ok(ProtocolAddress::new(phone_number.clone(), self.device_id))
    }
    /// Generate a protocol address using our uuid, converted to a string, as its "name"
    pub fn uuid_protocol_address(&self) -> Result<ProtocolAddress> {
        let addr_uuid = self.get_uuid()?;
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
    fn try_from(val: &str) -> std::result::Result<Self, Self::Error> {
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
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl TryFrom<&str> for AuxinDeviceAddress {
    type Error = Box<dyn Error>;
    fn try_from(val: &str) -> std::result::Result<Self, Self::Error> {
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
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
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