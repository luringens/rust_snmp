#![deny(missing_docs,
       missing_debug_implementations, missing_copy_implementations,
       trivial_casts, trivial_numeric_casts,
       unsafe_code,
       unstable_features,
       unused_import_braces, unused_qualifications)]
#![allow(dead_code)]

//! Contains functions and structs for sending and receiving SNMP messages.
extern crate byteorder;
//use std::net::UdpSocket;
//use std::{io, time};
mod snmpv1;
mod types;

/// Contains functions and structs for sending and receiving SNMPv3 messages.
pub mod snmpv3 {
    use types;
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

        // SNMP version
        let mut index = 2;
        index += types::write_u8(&mut buf[index..], 0x03);

        /*
        buf[index] = 0x30; // Sequence
        buf[index+1] = 0x11; // Length
        index += 2;
        */

        // Message ID
        index += types::write_i32(&mut buf[index..], 0x0BEEEEF0);
        
        // Max message size
        index += types::write_i32(&mut buf[index..], 0x00FFE3);

        // Message flags: reportable, not encrypted or authenticated
        index += types::write_octet_string(&mut buf[index..], &[0b0000_0100]);
        
        // Security model
        index += types::write_u8(&mut buf[index..], 0x03);

        // Security parameters
        index += types::write_octet_string(&mut buf[index..], &[0x03]);
        
        // Engine ID
        index += types::write_i32(&mut buf[index..], 0x300E0400);

        // Authoritative Engine Boots
        index += types::write_u8(&mut buf[index..], 0x00);

        // Authoritative Engine Time
        index += types::write_u8(&mut buf[index..], 0x00);
        
        // Username
        index += types::write_octet_string(&mut buf[index..], &[]);
        
        // Authentication Parameters
        index += types::write_octet_string(&mut buf[index..], &[]);
        
        // Privacy Parameters
        index += types::write_octet_string(&mut buf[index..], &[]);
        
        // Start sequence
        buf[index]   = 0x30; // Sequence
        buf[index+1] = 0x21; // Length
        index += 2;
        
        // Context Engine ID
        buf[index] = 0x04; // Octet
        buf[index+1] = 0x0D; // Length
        buf[index+2] = 0x80; // Conformance: SNMPv3
        buf[index+3] = 0x00; // ID Net-SNMP
        buf[index+4] = 0x1F;
        buf[index+5] = 0x88;
        buf[index+6] = 0x80; // Net-SNMP Random
        buf[index+7] = 0x59; // Engine ID data
        buf[index+8] = 0xDC;
        buf[index+9] = 0x48;
        buf[index+10] = 0x61;
        buf[index+11] = 0x45; // Creation time
        buf[index+12] = 0xA2;
        buf[index+13] = 0x63;
        buf[index+14] = 0x22;
        index += 17;

        // Context name
        index += types::write_octet_string(&mut buf[index..], &[]);

        buf[index]   = 0xA0; // GetRequest PDU
        buf[index+1] = 0x0E; // Length

        // Request ID
        index += types::write_i32(&mut buf[index..], 0x2C180DBB);
        
        // Error status and ID
        index += types::write_u8(&mut buf[index..], 0x00);
        index += types::write_u8(&mut buf[index..], 0x00);

        // Variable bindings
        buf[index+3] = 0x30; // Sequence
        buf[index+4] = 0x00; // Length
    }
}
