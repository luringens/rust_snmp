use std::io;
use std::string;
use traits::*;

/// Enum containing the various SNMP datatypes.

const SNMP_INTEGER_CODE: u8      = 0x02;
const SNMP_OCTET_STRING_CODE: u8 = 0x04;
const SNMP_NULL_CODE: u8         = 0x05;

#[derive(Debug, Clone)]
pub enum SnmpType {
    /// An integer.
    SnmpInteger(i64),
    /// An octet string.
    SnmpString(String),
    /// Null.
    SnmpNull,
    // Another object ID.
    //SnmpObjectID,
    // A sequence of some sort
    //SnmpSequence(Vec<SnmpType>),
}

/// Various errors that can occur.
#[derive(Debug)]
pub enum SnmpError {
    /// The packet is too short to parse.
    PacketTooShort,
    /// The type specified in the packet is invalid.
    InvalidType,
    /// The packet could not be parsed in the wanted manner.
    ParsingError,
    /// An IO error occured when sending or receiving the packets.
    Io(io::Error),
    /// An UTF8 parsing error occured when parsing a string.
    Utf8(string::FromUtf8Error),
}

impl From<io::Error> for SnmpError {
    fn from(error: io::Error) -> Self {
        SnmpError::Io(error)
    }
}

impl From<string::FromUtf8Error> for SnmpError {
    fn from(error: string::FromUtf8Error) -> Self {
        SnmpError::Utf8(error)
    }
}

pub fn extract_value(data: &[u8]) -> Result<(SnmpType, usize), SnmpError> {
    if data.len() < 2 { return Err(SnmpError::PacketTooShort); }
    let datatype = data[0];
    let length   = data[1];
    if data.len() - 2 < length as usize { return Err(SnmpError::PacketTooShort); }
    
    let datatype = match datatype {
        0x02 => SnmpType::SnmpInteger(i64::decode_snmp(data)?),
        0x04 => SnmpType::SnmpString(String::decode_snmp(data)?),
        0x05 => SnmpType::SnmpNull,
        _ => return Err(SnmpError::InvalidType),
    };
    Ok((datatype, length as usize))
}
