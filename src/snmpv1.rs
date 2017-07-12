//! Contains functions and structs for sending and receiving SNMPv1 messages.
use std::net::UdpSocket;
use std::{io, time};
use types::*;
use traits::*;

// Contains a SNMP response and some extracted metadata from it.
#[derive(Debug)]
pub struct Message {
    packet: Vec<u8>,
    data: SnmpDataType
}

/// Enum describing the various SNMP datatypes.
#[derive(Debug)]
pub enum SnmpDataType {
    /// An integer.
    SnmpInteger(i64),
    /// An octet string.
    SnmpString(String),
    /// Null.
    SnmpNull,
    // Another object ID.
    //SnmpObjectID,
    // A sequence of some sort
    //SnmpSequence,
}

/// Holds a SNMPv1 packet, and has some handy functions for parsing the contents.
impl Message {
    fn from_packet(packet: &[u8]) -> Result<Self, SnmpError> {
        if packet.len() < 26 {
            return Err(SnmpError::PacketTooShort);
        };

        let commlength = packet[6] as usize;
        if packet.len() < 25 + commlength {
            return Err(SnmpError::PacketTooShort);
        };

        let miblength = packet[23 + commlength] as usize;
        if packet.len() < 25 + commlength + miblength {
            return Err(SnmpError::PacketTooShort);
        };

        let datatype = packet[24 + commlength + miblength];
        let datalength = packet[25 + commlength + miblength] as usize;
        let datastart = 26 + commlength + miblength;
        if packet.len() < 26 + commlength + miblength + datalength {
            return Err(SnmpError::PacketTooShort);
        };

        let data = packet[datastart..datastart + datalength].to_vec();
        let datatype = match datatype {
            0x02 => SnmpDataType::SnmpInteger(i64::decode_snmp(data)?),
            0x04 => SnmpDataType::SnmpString(String::decode_snmp(data)?),
            0x05 => SnmpDataType::SnmpNull,
            //0x06 => SnmpDataType::SnmpObjectID,
            //0x30 => SnmpDataType::SnmpSequence,
            _ => return Err(SnmpError::InvalidType),
        };

        Ok(Message {
            packet: packet.to_vec(),
            data: datatype,
        })
    }

    /// Returns the full packet received.
    pub fn packet(&self) -> &[u8] {
        &self.packet
    }

    /// Parses the data of the packet as a utf8 string.
    pub fn to_string(&self) -> Result<String, SnmpError> {
        match self.data {
            SnmpDataType::SnmpInteger(ref i) => Ok((*i).to_string()),
            SnmpDataType::SnmpString(ref s) => Ok(s.clone()),
            _ => Err(SnmpError::InvalidType),
        }
    }

    /// If the message is a SnmpInteger, parses it and returns the number.
    pub fn to_int(&self) -> Result<i64, SnmpError> {
        match self.data {
            SnmpDataType::SnmpInteger(ref i) => Ok(*i),
            _ => Err(SnmpError::InvalidType),
        }
    }
}

/// Sends a SMTPv1 message and returns the reply or an error specifiying what went wrong.
///
/// #Examples
/// ```
/// let answer = rust_snmp::snmpv1::smtpv1_send("demo.snmplabs.com:161",
///                                           "public",
///                                           &[1, 3, 6, 1, 2, 1, 1, 5, 0])
///     .unwrap();
/// let answer = answer.to_string().unwrap();
/// assert_eq!("monkey5000", answer);
/// ```
pub fn smtpv1_send(addr: &str,
                    community: &str,
                    mibvals: &[u16])
                    -> Result<Message, SnmpError> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(time::Duration::from_millis(1000)))?;
    send(addr, mibvals, community, &socket)?;
    let mut packet: [u8; 1024] = [0; 1024];
    let length = receive(&socket, &mut packet)?;
    let packet = Message::from_packet(&packet[0..length])?;
    Ok(packet)
}

fn receive(socket: &UdpSocket, mut buffer: &mut [u8]) -> Result<usize, SnmpError> {
    let (amount, _) = socket.recv_from(&mut buffer)?;
    Ok(amount)
}

fn send(addr: &str,
        mibvals: &[u16],
        community: &str,
        socket: &UdpSocket)
        -> Result<usize, io::Error> {
    let mut buf = Vec::with_capacity(250);
    let mut mib = Vec::with_capacity(20);

    for mibval in mibvals.iter().skip(2) {
        if mibval > &127u16 {
            mib.push((128 + (*mibval / 128)) as u8);
            mib.push((*mibval - ((*mibval / 128) * 128)) as u8);
        } else {
            mib.push(*mibval as u8);
        }
    }
    let snmplen = 29 + community.len() + mib.len() + 2 - 1;

    // SNMP sequence start
    buf.push(0x30);
    buf.push((snmplen - 2) as u8);

    // SNMP version
    buf.append(&mut 0x00u8.encode_snmp());

    // Community
    buf.append(&mut community.as_bytes().encode_snmp());
    
    // MIB size sequence
    buf.push(0xA0); // GET request
    buf.push((19 + mib.len() + 2) as u8); // MIB size

    // Request ID
    buf.append(&mut 0x00000001i32.encode_snmp());
    
    // Error status and index
    buf.append(&mut 0x00u8.encode_snmp());
    buf.append(&mut 0x00u8.encode_snmp());

    // Variable binding
    buf.push(0x30);                      // Start of sequence
    buf.push((5 + mib.len() + 2) as u8); // Size
    buf.push(0x30);                      // Start of sequence
    buf.push((3 + mib.len() + 2) as u8); // Size
    buf.push(0x06);                      // Object type
    buf.push((mib.len() - 1 + 2) as u8); // Size

    // MIB
    buf.push(0x2B);
    buf.append(&mut mib);
    /*for i in mib.iter().skip(2) {
        buf.push(*i);
    }*/

    // Terminate with null
    buf.push(0x05);
    buf.push(0x00);

    socket.send_to(&buf, addr)
}
