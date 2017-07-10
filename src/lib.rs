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

        buf[5] = 0x30; // Sequence
        buf[6] = 0x11; // Length

        buf[7] = 0x02; // Integer
        buf[8] = 0x04; // Length
        buf[9] = 0x01; // Message ID
        buf[10] = 0x11;
        buf[11] = 0x41;
        buf[12] = 0x0F;

        buf[13] = 0x02; // Integer
        buf[14] = 0x03; // Length
        buf[15] = 0x00; // Max message size
        buf[16] = 0xFF;
        buf[17] = 0xE3;

        buf[18] = 0x04; // Octet
        buf[19] = 0x01; // Length
        buf[20] = 0b0000_0100; // Reportable, not encrypted or authenticated

        buf[21] = 0x02; // Integer
        buf[22] = 0x01; // Length
        buf[23] = 0x03; // USM

        buf[21] = 0x04; // Octet
        buf[22] = 0x10; // Length
        buf[23] = 0x03; // USM
        
        buf[21] = 0x02; // Integer
        buf[22] = 0x10; // Length
        buf[23] = 0x30; // Engine ID
        buf[24] = 0x0E;
        buf[25] = 0x04;
        buf[26] = 0x00;

        buf[27] = 0x02; // Integer
        buf[28] = 0x01; // Length
        buf[29] = 0x00; // Authoritative Engine Boots

        buf[27] = 0x02; // Integer
        buf[28] = 0x01; // Length
        buf[29] = 0x00; // Authoritative Engine Time
        
        // Username
        buf[28] = 0x04; // Octet
        buf[29] = 0x00; // Length
        
        // Authentication Parameters
        buf[28] = 0x04; // Octet
        buf[29] = 0x00; // Length
        
        // Privacy Parameters
        buf[28] = 0x04; // Octet
        buf[29] = 0x00; // Length
        
        buf[30] = 0x30; // Sequence
        buf[31] = 0x21; // Length
        
        // Context Engine ID
        buf[32] = 0x04; // Octet
        buf[33] = 0x0D; // Length
        buf[34] = 0x80; // Conformance: SNMPv3
        buf[35] = 0x00; // ID Net-SNMP
        buf[36] = 0x1F;
        buf[37] = 0x88;
        buf[38] = 0x80; // Net-SNMP Random
        buf[39] = 0x59; // Engine ID data
        buf[40] = 0xDC;
        buf[41] = 0x48;
        buf[42] = 0x61;
        buf[43] = 0x45; // Creation time
        buf[44] = 0xA2;
        buf[45] = 0x63;
        buf[46] = 0x22;

        // Context name
        buf[47] = 0x04; // Octet 
        buf[48] = 0x00; // Length

        buf[49] = 0xA0; // GetRequest PDU
        buf[50] = 0x0E; // Length

        buf[51] = 0x02; // Integer
        buf[52] = 0x04; // Length
        buf[53] = 0x2C; // Request ID
        buf[54] = 0x18;
        buf[55] = 0x0D;
        buf[56] = 0xBB;

        buf[57] = 0x02; // Integer
        buf[58] = 0x01; // Length
        buf[59] = 0x00; // Error status
        
        buf[60] = 0x02; // Integer
        buf[61] = 0x01; // Length
        buf[62] = 0x00; // Error ID

        // Variable bindings
        buf[63] = 0x30; // Sequence
        buf[64] = 0x00; // Length
    }
}
