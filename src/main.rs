use std::net::UdpSocket;
use std::time;

fn main() {
    let mut answer: [u8; 1024] = [0; 1024];
    match send("demo.snmplabs.com:161",
               &[1, 3, 6, 1, 2, 1, 1, 5, 0],
               &mut answer) {
        Ok(amt) => {
            println!("{}",
                     match parse(&answer[0..amt]) {
                         Ok(a) => a,
                         Err(b) => b.to_string(),
                     })
        }
        Err(error) => println!("Failure: {}", error),
    }
}

fn parse(packet: &[u8]) -> Result<String, &'static str> {
    if packet.len() < 6 {
        return Err("Packet length is too short.");
    };
    let commlength = packet[6] as usize;
    if packet.len() < 25 + commlength {
        return Err("Packet length is too short.");
    };
    let miblength = packet[23 + commlength] as usize;
    if packet.len() < 25 + commlength + miblength {
        return Err("Packet length is too short.");
    };
    let datatype = packet[24 + commlength + miblength];
    let datalength = packet[25 + commlength + miblength] as usize;
    let datastart = 26 + commlength + miblength;
    if packet.len() < 26 + commlength + miblength + datalength {
        return Err("Packet length is too short.");
    };

    match datatype {
        // Integer
        0x02 => {
            // The value may by a multi-byte integer, so each byte
            // may have to be shifted to the higher byte order.
            let mut value: u32 = 0;
            for i in datalength..0 {
                value = (value * 128) + packet[datastart + datalength - i] as u32;
            }
            Ok(value.to_string())
        }

        // String
        0x04 => {
            match String::from_utf8(packet[datastart..datastart + datalength].to_vec()) {
                Ok(s) => Ok(s),
                Err(_) => Err("Failed to parse UTF8"),
            }
        }

        0x05 => Err("Response is of type null"),
        0x06 | 0x30 | 0xA0 | 0xA2 | 0xA3 => Err("Response is of unhandled type"),
        _ => Err("Invalid response type"),
    }
}

fn send(addr: &str, mibvals: &[u16], mut response: &mut [u8]) -> std::io::Result<usize> {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("could not bind to address");
    socket.set_read_timeout(Some(time::Duration::from_millis(1000)))
        .expect("failed to set_read_timeout");

    let community = "public";

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

    socket.send_to(&buf[0..offset + 2], addr).expect("could not send packet");
    println!("Message sent!");
    match socket.recv_from(&mut response) {
        Ok((amt, _)) => Ok(amt),
        Err(error) => Err(error),
    }
}
