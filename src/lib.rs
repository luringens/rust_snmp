#![deny(missing_docs,
       missing_debug_implementations, missing_copy_implementations,
       trivial_casts, trivial_numeric_casts,
       unsafe_code,
       unstable_features,
       unused_import_braces, unused_qualifications)]

//! Contains functions and structs for sending and receiving SNMP messages.
use std::net::UdpSocket;
use std::{io, time};

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
}

impl From<io::Error> for SnmpError {
    fn from(error: io::Error) -> Self {
        SnmpError::Io(error)
    }
}

/// Contains functions and structs for sending and receiving SNMPv3 messages.
pub mod snmpv3 {
    use super::*;

    /// Sends a SMTPv3 message and returns the reply or an error specifiying what went wrong.
    ///
    /// #Examples
    /// ```
    /// rust_snmp::snmpv3::smtpv3_send("demo.snmplabs.com:161",
    ///                                           "public",
    ///                                           &[1, 3, 6, 1, 2, 1, 1, 5, 0]);
    /// ```
    pub fn smtpv3_send(addr: &str,
                       community: &str,
                       mibvals: &[u16]) {
        let mut buf: [u8; 1024] = [0; 1024];
        let mut mib: [u8; 1024] = [0; 1024];
        let orgmiblen = mibvals.len();
        let mut miblen = orgmiblen;

        let mut counter = 0;
        for mibval in mibvals.iter() {
            if mibval > &127u16 {
                mib[counter] = (128 + (mibval / 128)) as u8;
                mib[counter + 1] = (mibval - (mibval - ((mibval / 128) * 128))) as u8;
                counter += 2;
                miblen += 1;
            } else {
                mib[counter] = *mibval as u8;
                counter += 1;
            }
        }
        let mib = &mib[0..miblen];
        let miblen = miblen;
        let snmplen = 29 + community.len() + miblen - 1;

        // SNMP sequence start
        buf[0] = 0x30;
        buf[1] = (snmplen - 2) as u8;

        buf[2] = 0x02; // Integer
        buf[3] = 0x01; // Length
        buf[4] = 0x03; // SNMP version
        
        buf[5] = 0x02; // Integer type
        buf[6] = 0x04; // Length
        buf[7] = 0x00; // SNMP Request ID

        buf[5] = 0x02; // Integer type
        buf[6] = 0x08; // Length
        buf[7] = 0x04; // Message Max Size
        buf[8] = 0x00;
    }
}

/// Contains functions and structs for sending and receiving SNMPv1 messages.
pub mod snmpv1 {
    use super::*;

    /// Contains a SNMP response and some extracted metadata from it.
    #[derive(Debug)]
    pub struct Message {
        packet: Vec<u8>,
        datatype: MessageDataType,
        datalength: usize,
        datastart: usize,
    }

    /// Enum describing the various SNMP datatypes.
    #[derive(Debug, Clone, Copy)]
    pub enum MessageDataType {
        /// An integer.
        SnmpInteger,
        /// An octet string.
        SnmpString,
        /// Null.
        SnmpNull,
        /// Another object ID.
        SnmpObjectID,
        /// A sequence of some sort
        SnmpSequence,
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

            let datatype = match datatype {
                0x02 => MessageDataType::SnmpInteger,
                0x04 => MessageDataType::SnmpString,
                0x05 => MessageDataType::SnmpNull,
                0x06 => MessageDataType::SnmpObjectID,
                0x30 => MessageDataType::SnmpSequence,
                _ => return Err(SnmpError::InvalidType),
            };

            Ok(Message {
                packet: packet.to_vec(),
                datatype: datatype,
                datalength: datalength,
                datastart: datastart,
            })
        }

        /// Returns the full packet received.
        pub fn packet(&self) -> &[u8] {
            &self.packet
        }

        /// Returns the data part of the packet.
        pub fn data(&self) -> &[u8] {
            &self.packet[self.datastart..self.datalength]
        }

        /// Parses the data of the packet as a utf8 string.
        pub fn as_string(&self) -> Result<String, SnmpError> {
            match String::from_utf8(self.packet[self.datastart..(self.datastart +
                                                                    self.datalength)]
                .to_vec()) {
                Ok(s) => Ok(s),
                Err(_) => Err(SnmpError::ParsingError),
            }
        }

        /// If the message is a SnmpInteger, parses it and returns the number.
        pub fn as_int(&self) -> Result<i32, SnmpError> {
            match self.datatype {
                MessageDataType::SnmpInteger => {
                    // The value may by a multi-byte integer, so each byte
                    // may have to be shifted to the higher byte order.
                    let mut value: i32 = 0;
                    for i in self.datalength..0 {
                        value = (value * 128) +
                                self.packet[self.datastart + self.datalength - i] as i32;
                    }
                    Ok(value)
                }
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
    /// let answer = answer.as_string().unwrap();
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
        let mut buf: [u8; 1024] = [0; 1024];
        let mut mib: [u8; 1024] = [0; 1024];
        let orgmiblen = mibvals.len();
        let mut miblen = orgmiblen;

        let mut counter = 0;
        for mibval in mibvals.iter() {
            if mibval > &127u16 {
                mib[counter] = (128 + (mibval / 128)) as u8;
                mib[counter + 1] = (mibval - (mibval - ((mibval / 128) * 128))) as u8;
                counter += 2;
                miblen += 1;
            } else {
                mib[counter] = *mibval as u8;
                counter += 1;
            }
        }
        let mib = &mib[0..miblen];
        let miblen = miblen;
        let snmplen = 29 + community.len() + miblen - 1;

        // SNMP sequence start
        buf[0] = 0x30;
        buf[1] = (snmplen - 2) as u8;

        buf[2] = 0x02; // Integer
        buf[3] = 0x01; // Length
        buf[4] = 0x00; // SNMP version

        // Community
        buf[5] = 0x04;
        buf[6] = community.len() as u8;
        let mut offset = 7;
        for byte in community.as_bytes() {
            buf[offset] = *byte;
            offset += 1;
        }

        buf[offset] = 0xA0; // GET
        buf[offset + 1] = 19 + miblen as u8; // MIB size

        buf[offset + 2] = 0x02; // Integer type
        buf[offset + 3] = 0x04; // Length
        buf[offset + 4] = 0x00; // SNMP Request ID
        buf[offset + 5] = 0x00;
        buf[offset + 6] = 0x00;
        buf[offset + 7] = 0x01;

        buf[offset + 8] = 0x02; // Integer
        buf[offset + 9] = 0x01; // Length
        buf[offset + 10] = 0x00; // SNMP error status

        buf[offset + 11] = 0x02; // Integer
        buf[offset + 12] = 0x01; // Length
        buf[offset + 13] = 0x00; // SNMP error index

        // Variable binding
        buf[offset + 14] = 0x30;               // Start of sequence
        buf[offset + 15] = (5 + miblen) as u8; // Size
        buf[offset + 16] = 0x30;               // Start of sequence
        buf[offset + 17] = (3 + miblen) as u8; // Size
        buf[offset + 18] = 0x06;               // Object type
        buf[offset + 19] = (miblen - 1) as u8; // Size

        // MIB
        buf[offset + 20] = 0x2b;
        offset += 21;
        for index in mib.iter().skip(2) {
            buf[offset] = *index;
            offset += 1;
        }

        buf[offset] = 0x05; // Null object
        buf[offset + 1] = 0x00; // Null

        socket.send_to(&buf[0..offset + 2], addr)
    }
}
