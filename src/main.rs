#[allow(unused_imports)]
use std::net::UdpSocket;

#[derive(Clone)]
struct DnsHeader {
    packet_identifer: u16,
    is_reply_packet: bool,        //packed to 1 bit when serializing
    operation_code: u8,           //packed to 4 bits when serializing
    is_authoritative: bool,       //packed to 1 bit when serializing
    is_truncated: bool,           //packed to 1 bit when serializing
    recursion_is_desired: bool,   //packed to 1 bit when serializing
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
            recursion_is_desired: header_flags[4] != 0,
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
        flag_bits |= (header.is_reply_packet as u16) << 15; //Set Query response indicator
        flag_bits |= (header.operation_code as u16) << 11; //Set Operation code
        flag_bits |= (header.is_authoritative as u16) << 10; //Set Authortitative answer
        flag_bits |= (header.is_truncated as u16) << 9; //Set Truncation flag
        flag_bits |= (header.recursion_is_desired as u16) << 8; //Set Recursion desired flag
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
        println!("recursion_is_desired:{}", header.recursion_is_desired);
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

#[derive(Clone)]
struct DNSQuestion {
    domain_name: Vec<String>,
    question_type: u16,
    question_class: u16,
}

impl DNSQuestion {
    pub fn from_bytes(data: &[u8; 500], qcount: usize) -> Vec<DNSQuestion> {
        let capacity_heuristic_bound = 10;
        let mut questions_list = Vec::with_capacity(capacity_heuristic_bound);
        let mut current_domain_labels = Vec::with_capacity(capacity_heuristic_bound);
        let mut index = 0;

        while questions_list.len() < qcount && index < data.len() {
            let label_length = data[index] as usize;
            if label_length == 0 {
                if current_domain_labels.is_empty() {
                    break; //data is malformed, implement error handling for this
                }
                questions_list.push(DNSQuestion {
                    domain_name: current_domain_labels.clone(),
                    question_type: u16::from_be_bytes([data[index + 1], data[index + 2]]),
                    question_class: u16::from_be_bytes([data[index + 3], data[index + 4]]),
                });
                current_domain_labels.clear();
                index += 5; //Jump to beginning of next label
            } else {
                let label_slice = &data[index + 1..(index + label_length + 1)];
                current_domain_labels.push(String::from_utf8_lossy(label_slice).to_string());
                index += label_length + 1; //Jump to beginning of next label
            }
        }
        questions_list
    }

    pub fn to_bytes(question: &DNSQuestion) -> Vec<u8> {
        let mut bytes_buffer: Vec<u8> = question
            .domain_name
            .clone()
            .into_iter()
            .flat_map(|s| s.into_bytes())
            .collect();

        bytes_buffer.extend(question.question_type.to_be_bytes());
        bytes_buffer.extend(question.question_class.to_be_bytes());
        bytes_buffer
    }

    pub fn sequence_to_bytes(question_list: Vec<DNSQuestion>) -> Vec<u8> {
        question_list
            .iter()
            .flat_map(DNSQuestion::to_bytes)
            .collect()
    }

    pub fn print_question(question: &DNSQuestion) {
        println!("DNS Question");
        println!("----------");
        println!("Domain Name");
        println!("{:?}", question.domain_name);
        println!("Question type:{}", question.question_type);
        println!("Question class:{}", question.question_class);
        println!("----------");
    }

    pub fn print_questions_sequence(questions_list: &[DNSQuestion]) {
        for question in questions_list {
            DNSQuestion::print_question(question);
        }
    }
}

#[derive(Clone)]
struct DNSAnswer {
    domain_name: Vec<String>,
    answer_type: u16,
    answer_class: u16,
    time_to_live: u32,
    length: u16,
    data: Vec<u8>,
}

impl DNSAnswer {
    pub fn print_answer(answer: &DNSAnswer) {
        println!("DNS Answer");
        println!("----------");
        println!("Domain Name");
        println!("{:?}", answer.domain_name);
        println!("Answer Type:{}", answer.answer_type);
        println!("Answer Class:{}", answer.answer_class);
        println!("Answer TTL :{} (seconds)", answer.time_to_live);
        println!("Answer Length: {} (bytes)", answer.length);
        print!("Data");
        println!("{:02X?}", answer.data);
        println!("----------");
    }

    pub fn print_answers_sequence(answers: &[DNSAnswer]) {
        for answer in answers {
            DNSAnswer::print_answer(answer);
        }
    }
}

#[derive(Clone)]
struct DnsMessage {
    header: DnsHeader,
    questions: Vec<DNSQuestion>,
    answers: Vec<DNSAnswer>,
    additional: Vec<u8>,
}

impl DnsMessage {
    pub fn from_bytes(data: &[u8; 512]) -> DnsMessage {
        let data_header: [u8; 12] = data[0..12]
            .try_into()
            .expect("query has 12 bytes for a header");
        let data_question: [u8; 500] = data[12..]
            .try_into()
            .expect("query has 500 bytes for question");
        let dns_header = DnsHeader::from_bytes(&data_header);
        let qcount = dns_header.question_count as usize;
        DnsMessage {
            header: dns_header,
            questions: (DNSQuestion::from_bytes(&data_question, qcount)),
            answers: Vec::new(),
            additional: Vec::new(),
        }
    }

    pub fn to_bytes(message: &DnsMessage) -> ([u8; 512],usize) {
        let header_bytes = DnsHeader::to_bytes(&message.header); 
        let num_header_bytes=header_bytes.len();
        let questions_vec_bytes = DNSQuestion::sequence_to_bytes(message.questions.clone());
        let mut message_buffer = [0; 512];
        message_buffer[0..num_header_bytes].copy_from_slice(&header_bytes); //Header fixed at 12 bytes
        message_buffer[num_header_bytes..(num_header_bytes + questions_vec_bytes.len())].copy_from_slice(&questions_vec_bytes);
        (message_buffer,12)
    }

    fn build_response_header(dns_query_header: &DnsHeader, qdcount: u16, acount: u16) -> DnsHeader {
        DnsHeader {
            packet_identifer: dns_query_header.packet_identifer,
            is_reply_packet: true, //Set to true for response packet
            operation_code: dns_query_header.operation_code,
            is_authoritative: dns_query_header.is_authoritative,
            is_truncated: dns_query_header.is_truncated,
            recursion_is_desired: dns_query_header.recursion_is_desired,
            recursion_is_available: false, //Recursion not currently supported
            reserved: dns_query_header.reserved,
            response_code: dns_query_header.response_code,
            question_count: qdcount,
            answer_record_count: acount,
            authority_record_count: dns_query_header.authority_record_count, //Look into modifying these
            additional_record_count: dns_query_header.additional_record_count, //Looking into modifying these
        }
    }

    pub fn build_response(dns_query: &DnsMessage) -> DnsMessage {
        let response_questions = dns_query.questions.clone();
        let response_answers = dns_query.answers.clone(); //Will implement this later
        let response_additional = dns_query.additional.clone();
        let response_header = DnsMessage::build_response_header(
            &dns_query.header,
            response_questions.len() as u16,
            response_answers.len() as u16,
        );
        DnsMessage {
            header: response_header,
            questions: response_questions,
            answers: response_answers,
            additional: response_additional,
        }
    }

    pub fn response_to_query_bytes(query: &[u8; 512]) -> ([u8; 512],usize) {
        let dns_query_message = DnsMessage::from_bytes(query);
        let dns_response_message = DnsMessage::build_response(&dns_query_message);
        //Header gives the number of bytes
        DnsMessage::to_bytes(&dns_response_message)
    }

    fn print_additional_section(message: &DnsMessage) {
        println!("----------");
        println!("Additional Bytes");
        println!("{:02X?}", message.additional);
        println!("----------");
    }

    pub fn print_message(message: &DnsMessage) {
        println!("DNS Message");
        println!("----------");
        println!("----------");
        DnsHeader::print_header(&message.header);
        DNSQuestion::print_questions_sequence(&message.questions);
        DNSAnswer::print_answers_sequence(&message.answers);
        DnsMessage::print_additional_section(message);
        println!("----------");
        println!("----------");
    }
}

fn main() {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                let (response_buffer,num_encoded_bytes) = DnsMessage::response_to_query_bytes(&buf);
                let response =&response_buffer[0..num_encoded_bytes];
                udp_socket
                    .send_to(response, source) //Temporary until I have truncated
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
