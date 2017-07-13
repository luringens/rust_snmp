use byteorder::{BigEndian, ByteOrder};
use types::*;

pub(crate) trait EncodeSnmp {
    fn encode_snmp(&self) -> Vec<u8>;
}

pub(crate) trait DecodeSnmp {
    fn decode_snmp(&[u8]) -> Result<Self, SnmpError> where Self: Sized;
}

impl EncodeSnmp for u8 {
    fn encode_snmp(&self) -> Vec<u8> {
        vec![
            0x02, // Integer type
            0x01, // Length
            *self // Value
        ]        
    }    
}

impl EncodeSnmp for i16 {
    fn encode_snmp(&self) -> Vec<u8> {
        let mut values: [u8;2] = [0;2];
        BigEndian::write_i16(&mut values, *self);
        vec![
            0x02, // Integer type
            0x02, // Length
            values[0],
            values[1]
        ]        
    }    
}

impl EncodeSnmp for i32 {
    fn encode_snmp(&self) -> Vec<u8> {
        let mut values: [u8;4] = [0;4];
        BigEndian::write_i32(&mut values, *self);
        vec![
            0x02, // Integer type
            0x04, // Length
            values[0],
            values[1],
            values[2],
            values[3]
        ]        
    }    
}

impl EncodeSnmp for u32 {
    fn encode_snmp(&self) -> Vec<u8> {
        let mut values: [u8;4] = [0;4];
        BigEndian::write_u32(&mut values, *self);
        vec![
            0x02, // Integer type
            0x04, // Length
            values[0],
            values[1],
            values[2],
            values[3]
        ]        
    }    
}

impl EncodeSnmp for [u8] {
    fn encode_snmp(&self) -> Vec<u8> {
        let mut values = vec![0x04, self.len() as u8];
        values.extend(self);
        values
    }    
}

impl DecodeSnmp for i64 {
    fn decode_snmp(data: &[u8]) -> Result<Self, SnmpError> {
        if data.len() > 8 || data.len() < 1 { return Err(SnmpError::ParsingError) };
        Ok(BigEndian::read_int(&data, data.len()))
    }
}

impl DecodeSnmp for String {
    fn decode_snmp(data: &[u8]) -> Result<Self, SnmpError> {
        Ok(String::from_utf8(data.to_vec())?)
    }
}
