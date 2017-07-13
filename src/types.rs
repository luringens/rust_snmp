use std::{io, string, slice};
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
    /// An OID.
    SnmpObjectID(Vec<u8>),
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
    /// The SNMP response contained an error
    ResponseError(i64),
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

pub fn extract_value(mut data: &mut slice::Iter<u8>) -> Result<SnmpType, SnmpError> {
    let datatype = *data.next().ok_or(SnmpError::PacketTooShort)?;
    let length   = *data.next().ok_or(SnmpError::PacketTooShort)? as usize;

    println!();
    println!("Type:   {:00X}", datatype);
    println!("Length: {:00}", length);

    if data.len() < length {
        return Err(SnmpError::PacketTooShort);
    }
    
    let ndata: Vec<_> = data.take(length).map(|i| *i).collect();
    let datatype = match datatype {
        0x02 => SnmpType::SnmpInteger(i64::decode_snmp(&ndata)?),
        0x04 => SnmpType::SnmpString(String::decode_snmp(&ndata)?),
        0x05 => SnmpType::SnmpNull,
        0x06 => SnmpType::SnmpObjectID(ndata),
        _ => return Err(SnmpError::InvalidType),
    };

    println!("Data: {:?}", datatype);
    Ok(datatype)
}
