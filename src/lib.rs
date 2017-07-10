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

