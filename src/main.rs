#[allow(unused_imports)]
use std::net::UdpSocket;

struct DnsHeader {
    packet_identifer: u16,
    is_reply_packet: bool, //packed to 1 bit when serializing
    operation_code: u8,
    is_authoritative: bool,       //packed to 1 bit when serializing
    is_truncated: bool,           //packed to 1 bit when serializing
    recusion_is_desired: bool,    //packed to 1 bit when serializing
    recursion_is_available: bool, //packed to 1 bit when serializing
    reserved: u8,                 //packed to 3 bits when serializing
    response_code: u8,
    question_count: u16,
    answer_record_count: u16,
    authority_record_count: u16,
    additional_record_count: u16,
}

impl DnsHeader {
    pub fn from_bytes(data: &[u8; 12]) -> DnsHeader {
        let flags_slice: &[u8; 2] = data[2..4]
            .try_into()
            .expect("DNS message header contains 12 bytes");
        let header_flags = DnsHeader::get_flags(flags_slice);
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
        todo!()
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
        println!("recursion_is_available:{}",header.recursion_is_available);
        println!("reserved:{}", header.reserved);
        println!("response_code:{}", header.response_code);
        println!("question_count:{}", header.question_count);
        println!("answer_record_count:{}", header.answer_record_count);
        println!("authority_record_count:{}", header.authority_record_count);
        println!("additional_record_count:{}", header.additional_record_count);
        println!("----------");
    }

    fn get_flags(data: &[u8; 2]) -> [u8; 8] {
        let mut header_flags: [u8; 8] = [0; 8];
        header_flags[0] = data[0] & 1; //Query response indicator
        header_flags[1] = (data[0] >> 1) & 0xF; //Operatiom code
        header_flags[2] = (data[0] >> 5) & 1; //Authoritative Answer
        header_flags[3] = (data[0] >> 6) & 1; //Truncation flag
        header_flags[4] = (data[0] >> 7) & 1; //Recursion desired
        header_flags[5] = data[1] & 1; //Recursion available
        header_flags[6] = (data[1] >> 1) & 0x7; //Reserved
        header_flags[7] = (data[1] >> 4) & 0xF; //Response code
        header_flags
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
                    DnsHeader::print_header(&response_header);
                    []
                } else {
                    []
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
