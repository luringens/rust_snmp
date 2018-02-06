use std::io;
use std::string;

/// Enum containing the various SNMP datatypes.
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

/*pub fn extract_value(data: &[u8]) -> Result<SnmpType, SnmpError> {
    if data.len() < 2 { return Err(SnmpError::PacketTooShort); }
    let length   = data[1];
    let datatype = data[0];
    if data.len() - 2 < length as usize { return Err(SnmpError::PacketTooShort); }
    
    match datatype {
        0x02 => extract_integer(&data[2..]),
        0x04 => extract_string(&data[2..]),
        0x05 => Ok(SnmpType::SnmpNull),
        0x06 => Err(SnmpError::NotYetImplementedError),
        0x30 => Err(SnmpError::NotYetImplementedError),
        _ => return Err(SnmpError::InvalidType),
    }
}*/
