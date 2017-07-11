use byteorder::{LittleEndian, ByteOrder};
use std::io;
use std::io::Write;

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
    /// You've hit a dead end
    NotYetImplementedError,
}

impl From<io::Error> for SnmpError {
    fn from(error: io::Error) -> Self {
        SnmpError::Io(error)
    }
}

pub fn extract_value(data: &[u8]) -> Result<SnmpType, SnmpError> {
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
}

fn extract_integer(data: &[u8]) -> Result<SnmpType, SnmpError>{
    if data.len() > 8 || data.len() < 1 { return Err(SnmpError::ParsingError) };
    let value = LittleEndian::read_int(data, data.len());
    Ok(SnmpType::SnmpInteger(value))
}

fn extract_string(data: &[u8]) -> Result<SnmpType, SnmpError>{
    match String::from_utf8(data.to_vec()) {
        Ok(s) => Ok(SnmpType::SnmpString(s)),
        Err(_) => Err(SnmpError::ParsingError),
    }
}

pub fn write_i32(mut buf: &mut [u8], value: i32) -> usize {
    buf[0] = 0x02; // Datatype for integer
    buf[1] = 0x04; // Length of an i32
    LittleEndian::write_i32(&mut buf, value);
    6
}

pub fn write_i24(mut buf: &mut [u8], value: i32) -> usize {
    buf[0] = 0x02; // Datatype for integer
    buf[1] = 0x03; // Length of an i24
    LittleEndian::write_i24(&mut buf, value);
    5
}

pub fn write_i16(mut buf: &mut [u8], value: i16) -> usize {
    buf[0] = 0x02; // Datatype for integer
    buf[1] = 0x02; // Length of an i16
    LittleEndian::write_i16(&mut buf, value);
    4
}

pub fn write_u8(mut buf: &mut [u8], value: u8) -> usize {
    buf[0] = 0x02; // Datatype for integer
    buf[1] = 0x01; // Length of an u8
    buf[2] = value;
    3
}

pub fn write_octet_string(mut buf: &mut [u8], value: &[u8]) -> usize {
    buf[0] = 0x04;        // Datatype for octet strings
    buf[1] = value.len() as u8; // Length of the octet
    if value.len() != 01 {
        (&mut buf[2..]).write_all(value).expect("Failed to write octet.");
    }
    value.len() + 2
}