//! Contains functions and structs for sending and receiving SNMPv1 messages.
use std::net::UdpSocket;
use std::{io, time};
use types::*;
use traits::*;
use rand;

// Contains a SNMP response and some extracted metadata from it.
#[derive(Debug)]
pub struct Message {
    packet: Vec<u8>,
    community: String,
    data: SnmpType
}

/// Holds and parses SNMPv1 packets.
impl Message {
    fn from_packet(packet: &[u8]) -> Result<Self, SnmpError> {
        // Confirm packet is as long as it needs to be
        if packet.len() < 2 || packet.len() - 1 != packet[1] as usize {
            return Err(SnmpError::PacketTooShort);
        }

        // Confirm first bit is the SNMP flag
        if packet[0] != 0x30 {
            return Err(SnmpError::ParsingError);
        }

        let mut iterator = packet.iter();

        // Confirm the protocol is SNMPv1
        let mut index = 2;
        let (protocol, offset) = extract_value(&packet[index..])?;
        index += offset;
        match protocol {
            SnmpType::SnmpInteger(i) => if i != 0 { return Err(SnmpError::ParsingError); },
            _ => return Err(SnmpError::ParsingError),
        };
        
        // Get community
        let (community, offset) = extract_value(&packet[index..])?;
        index += offset;
        let community = match community {
            SnmpType::SnmpString(s) => s,
            _ => return Err(SnmpError::ParsingError),
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
            0x02 => SnmpType::SnmpInteger(i64::decode_snmp(&data)?),
            0x04 => SnmpType::SnmpString(String::decode_snmp(&data)?),
            0x05 => SnmpType::SnmpNull,
            _ => return Err(SnmpError::InvalidType),
        };

        Ok(Message {
            packet: packet.to_vec(),
            community: community,
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
            SnmpType::SnmpInteger(ref i) => Ok((*i).to_string()),
            SnmpType::SnmpString(ref s) => Ok(s.clone()),
            _ => Err(SnmpError::InvalidType),
        }
    }

    /// If the message is a SnmpInteger, parses it and returns the number.
    pub fn to_int(&self) -> Result<i64, SnmpError> {
        match self.data {
            SnmpType::SnmpInteger(ref i) => Ok(*i),
            _ => Err(SnmpError::InvalidType),
        }
    }
}

#[derive(Debug)]
/// Contains fields describing a SNMPv1 request as well as 
/// functions to send it.
pub struct Request {
    pub address: String,
    pub mibvals: Vec<u16>,
    pub community: String,
    pub request_id: u32,
    pub timeout: u64,
}

impl Request {
    /// Creates a request with only the essential arguments.
    /// Defaults requestID to a random number, and timeout to 1000ms.
    pub fn new(address: String, community: String, mibvals: Vec<u16>) -> Request {        
        Request {
            address: address,
            mibvals: mibvals,
            community: community,
            request_id: rand::random::<u32>(),
            timeout: 1000
        }
    }

    /// Sends a SMTPv1 message and returns the reply or an error specifiying what went wrong.
    ///
    /// #Examples
    /// ```
    /// use rust_snmp::snmpv1::Request;
    /// let request = Request::new("demo.snmplabs.com:161".to_owned(),
    ///                                  "public".to_owned(),
    ///                                  vec![1, 3, 6, 1, 2, 1, 1, 5, 0]);
    /// let message = request.send().unwrap();
    /// let host = message.to_string().unwrap();
    /// assert_eq!("monkey5000", host);
    /// ```
    pub fn send(&self) -> Result<Message, SnmpError> {
        // Bind to any UDP socket, set timeout to avoid hanging.
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(time::Duration::from_millis(1000)))?;
        
        // Create and send packet
        let sendpacket = self.createpacket()?;
        socket.send_to(&sendpacket, &self.address)?;

        // Receive and parse packet
        let mut receivepacket: [u8; 1024] = [0; 1024];
        let (length, _) = socket.recv_from(&mut receivepacket)?;
        // DEBUG TODO REMOVE
        for i in &receivepacket[0..length] {print!("{:02X} ", i);}
        Ok(Message::from_packet(&receivepacket[0..length])?)
    }

    fn createpacket(&self) -> Result<Vec<u8>, io::Error> {
        let mut buf = Vec::with_capacity(250);
        let mut mib = Vec::with_capacity(20);

        // Convert MIBs to bytes since each number can be more than one byte big.
        for mibval in self.mibvals.iter().skip(2) {
            if mibval > &127u16 {
                mib.push((128 + (*mibval / 128)) as u8);
                mib.push((*mibval - ((*mibval / 128) * 128)) as u8);
            } else {
                mib.push(*mibval as u8);
            }
        }
        let snmplen = 29 + self.community.len() + mib.len() + 2 - 1;

        // SNMP sequence start
        buf.push(0x30);
        buf.push((snmplen - 2) as u8);

        // SNMP version
        buf.append(&mut 0x00u8.encode_snmp());

        // Community
        buf.append(&mut self.community.as_bytes().encode_snmp());
        
        // MIB size sequence
        buf.push(0xA0); // GET request
        buf.push((19 + mib.len() + 2) as u8); // MIB size

        // Request ID
        buf.append(&mut self.request_id.encode_snmp());
        
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

        // Terminate with null
        buf.push(0x05);
        buf.push(0x00);
        Ok(buf)
    }
}
