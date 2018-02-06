//! Contains functions and structs for sending and receiving SNMPv3 messages.

use types;
use std::net::UdpSocket;
use std::time;
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
    /*let mut mib: [u8; 1024] = [0; 1024];
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
    let snmplen = 29 + community.len() + miblen - 1;*/

    // SNMP sequence start
    buf[0] = 0x30;
    
    // SNMP version
    let mut index = 2;
    index += types::write_u8(&mut buf[index..], 0x03);

    buf[index] = 0x30; // Sequence
    buf[index+1] = 0x11; // Length
    index += 2;

    // Message ID
    index += types::write_i32(&mut buf[index..], 0x009E5D19);
    
    // Max message size
    index += types::write_i24(&mut buf[index..], 0x00FFE3);

    // Message flags: reportable, not encrypted or authenticated
    index += types::write_octet_string(&mut buf[index..], &[0b0000_0100]);
    
    // Security model
    index += types::write_u8(&mut buf[index..], 0x03);
    
    // Security parameters
    //index += types::write_octet_string(&mut buf[index..], &[0x03]);
    
    // UNKNWN
    index += types::write_raw_octets(&mut buf[index..], &[0x04, 0x2D, 0x30, 0x2B, 0x04, 0x0E]);

    // Engine ID
    index += types::write_raw_octets(&mut buf[index..], &[0x80, 0x00, 0x4f, 0xb8, 0x05,
                                                            0x63, 0x6c, 0x6f, 0x75, 0x64,
                                                            0x4d, 0xab, 0x22, 0xcc]);
    
    // Authoritative Engine Boots
    index += types::write_u8(&mut buf[index..], 0x00);

    // Authoritative Engine Time
    index += types::write_u8(&mut buf[index..], 0x00);
    
    // Username
    index += types::write_octet_string(&mut buf[index..], "usr-none-none".as_bytes());
    
    // Authentication Parameters
    index += types::write_octet_string(&mut buf[index..], &[]);
    
    // Privacy Parameters
    index += types::write_octet_string(&mut buf[index..], &[]);
    
    // Start sequence
    buf[index]   = 0x30; // Sequence
    buf[index+1] = 0x21; // Length
    index += 2;
    
    // Context Engine ID
    index += types::write_raw_octets(&mut buf[index..], &[0x80, 0x00, 0x4f, 0xb8, 0x05,
                                                            0x63, 0x6c, 0x6f, 0x75, 0x64,
                                                            0x4d, 0xab, 0x22, 0xcc]);

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

    // Packet length
    buf[1] = (index-3) as u8;

    return;

    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.set_read_timeout(Some(time::Duration::from_millis(1000))).unwrap();
    socket.send_to(&buf[0..index], addr).unwrap();
    
    let mut packet: [u8; 1024] = [0; 1024];
    let (length, _) = socket.recv_from(&mut packet).unwrap();
    for i in 0..length {
        print!("{} ", packet[i]);
    }        
}
