#[allow(unused_imports)]
use std::net::UdpSocket;

struct DnsHeader {
    packet_identifer: u16,
    is_reply_packet: bool,        //packed to 1 bit when serializing
    operation_code: u8,           //packed to 4 bits when serializing
    is_authoritative: bool,       //packed to 1 bit when serializing
    is_truncated: bool,           //packed to 1 bit when serializing
    recusion_is_desired: bool,    //packed to 1 bit when serializing
    recursion_is_available: bool, //packed to 1 bit when serializing
    reserved: u8,                 //packed to 3 bits when serializing
    response_code: u8,            //packed to 4 bits when serializing
    question_count: u16,
    answer_record_count: u16,
    authority_record_count: u16,
    additional_record_count: u16,
}

impl DnsHeader {
    pub fn from_bytes(data: &[u8; 12]) -> DnsHeader {
        let flag_bytes: [u8; 2] = data[2..4]
            .try_into()
            .expect("DNS message header contains 12 bytes");
        let header_flags = DnsHeader::get_flags(u16::from_be_bytes(flag_bytes));
        DnsHeader {
            packet_identifer: u16::from_be_bytes([data[0], data[1]]),
            is_reply_packet: header_flags[0] != 0,
            operation_code: header_flags[1],
            is_authoritative: header_flags[2] != 0,
            is_truncated: header_flags[3] != 0,
            recusion_is_desired: header_flags[4] != 0,
            recursion_is_available: header_flags[5] != 0,
            reserved: header_flags[6],
            response_code: header_flags[7],
            question_count: u16::from_be_bytes([data[4], data[5]]),
            answer_record_count: u16::from_be_bytes([data[6], data[7]]),
            authority_record_count: u16::from_be_bytes([data[8], data[9]]),
            additional_record_count: u16::from_be_bytes([data[10], data[11]]),
        }
    }

    pub fn to_bytes(header: &DnsHeader) -> [u8; 12] {
        let header_byte_fields: Vec<[u8; 2]> = vec![
            header.packet_identifer.to_be_bytes(),
            DnsHeader::pack_flags(header), //converted to big-endian
            header.question_count.to_be_bytes(),
            header.answer_record_count.to_be_bytes(),
            header.authority_record_count.to_be_bytes(),
            header.additional_record_count.to_be_bytes(),
        ];
        header_byte_fields
            .into_flattened()
            .try_into()
            .expect("Header serialization is 12 bytes")
    }

    fn get_flags(flag_bits: u16) -> [u8; 8] {
        let mut header_flags: [u8; 8] = [0; 8];
        header_flags[0] = ((flag_bits >> 15) & 1) as u8; //Query response indicator
        header_flags[1] = ((flag_bits >> 11) & 0xF) as u8; //Operation code
        header_flags[2] = ((flag_bits >> 10) & 1) as u8; //Authoritative answer
        header_flags[3] = ((flag_bits >> 9) & 1) as u8; //Truncation flag
        header_flags[4] = ((flag_bits >> 8) & 1) as u8; //Recursion desired
        header_flags[5] = ((flag_bits >> 7) & 1) as u8; //Recursion available
        header_flags[6] = ((flag_bits >> 4) & 0x7) as u8; //Reserved
        header_flags[7] = (flag_bits & 0xF) as u8; //Response code
        header_flags
    }

    fn pack_flags(header: &DnsHeader) -> [u8; 2] {
        let mut flag_bits: u16 = 0;
        flag_bits |= 1 << 15; //Set Query response indicator (Fixed for Reply Packet)
        flag_bits |= (header.operation_code as u16) << 11; //Set Operation code
        flag_bits |= (header.is_authoritative as u16) << 10; //Set Authortitative answer
        flag_bits |= (header.is_truncated as u16) << 9; //Set Truncation flag
        flag_bits |= (header.recusion_is_desired as u16) << 8; //Set Recursion desired flag
        flag_bits |= (header.recursion_is_available as u16) << 7; //Set Recursion available flag
        flag_bits |= (header.reserved as u16) << 4; //Set Reserved
        flag_bits |= header.response_code as u16; //Set Response code
        flag_bits.to_be_bytes()
    }

    pub fn print_header(header: &DnsHeader) {
        println!("DNS Header");
        println!("----------");
        println!("packet_identifer:{}", header.packet_identifer);
        println!("is_reply_packet:{}", header.is_reply_packet);
        println!("operation_code:{}", header.operation_code);
        println!("is_authoritative:{}", header.is_authoritative);
        println!("is_truncated:{}", header.is_truncated);
        println!("recusion_is_desired:{}", header.recusion_is_desired);
        println!("recursion_is_available:{}", header.recursion_is_available);
        println!("reserved:{}", header.reserved);
        println!("response_code:{}", header.response_code);
        println!("question_count:{}", header.question_count);
        println!("answer_record_count:{}", header.answer_record_count);
        println!("authority_record_count:{}", header.authority_record_count);
        println!("additional_record_count:{}", header.additional_record_count);
        println!("----------");
    }
}

struct DnsMessage {
    header: DnsHeader,
}

impl DnsMessage {}

fn main() {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                let response = if size >= 12 {
                    let header_slice: &[u8; 12] = buf[0..12].try_into().expect("msg");
                    let response_header = DnsHeader::from_bytes(header_slice);
                    DnsHeader::to_bytes(&response_header)
                } else {
                    println!("Entered other conditional");
                    [0; 12]
                };
                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
