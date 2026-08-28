#[allow(unused_imports)]
use std::net::UdpSocket;
use std::{
    collections::{HashMap, HashSet},
    env, vec,
};

//"Bound" on the number of labels in domain
//Aims to minimize reallocations during deserialization
const CAPACITY_HEURISTIC_BOUND: usize = 10;

const DATAGRAM_HEADER_BYTE_COUNT: usize = 12;

const DATAGRAM_HEADER_MAX_SIZE: usize = 512;

const MAX_TRANSMISSION_ATTEMPTS: usize = 10;

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
    domain_labels: Vec<String>,
    question_type: u16,
    question_class: u16,
}

impl DNSQuestion {
    pub fn from_bytes(data: &[u8; 512]) -> (Vec<DNSQuestion>, usize) {
        let question_count = u16::from_be_bytes([data[4], data[5]]) as usize;
        let mut questions_list = Vec::with_capacity(question_count);
        let mut current_domain_labels = Vec::with_capacity(CAPACITY_HEURISTIC_BOUND);
        let mut label_pointer_stack = Vec::with_capacity(CAPACITY_HEURISTIC_BOUND);
        let mut label_pointer_set = HashSet::with_capacity(CAPACITY_HEURISTIC_BOUND);
        let mut index = DATAGRAM_HEADER_BYTE_COUNT;

        while questions_list.len() < question_count && index < data.len() {
            let label_octet = data[index] as usize;
            let label_is_pointer = data[index] >> 6 == 0x3; //Check if pointer bits are set
            if label_octet == 0 {
                //A pointer moves the index to the next byte to read after it's associated
                //data has been parsed
                let possible_label_pointer=index-2;
                let field_offset=if label_pointer_set.contains(&possible_label_pointer) {0} else {1};
                if current_domain_labels.is_empty() {
                    return (questions_list, index - 12); //Null terminator read (indicates malformed section might want error handling?)
                } else if label_pointer_stack.is_empty() {
                    questions_list.push(DNSQuestion {
                        domain_labels: current_domain_labels.clone(),
                        question_type: u16::from_be_bytes([data[index + field_offset], data[index + field_offset + 1]]),
                        question_class: u16::from_be_bytes([data[index + field_offset +2 ], data[index + field_offset + 3]]),
                    });
                //     println!("question_type:{} and question_class:{}",u16::from_be_bytes([data[index + 1], data[index + 2]]),
                // u16::from_be_bytes([data[index + 3], data[index + 4]]));
                    // let a=u16::from_be_bytes([data[index + 1], data[index + 2]]);
                    // let b=u16::from_be_bytes([data[index + 3], data[index + 4]]);
                    // if(a==256 || b==256){
                    //     println!("label pointer set {:?}",label_pointer_set);
                    // for i in 12..index+5{
                    //     println!("data[{}]={}",i,data[i]);
                    // }
                    // println!("{:?}",&data[index+1..index+5]);
                    // let aa=u16::from_be_bytes([data[index], data[index + 1]]);
                    // let bb=u16::from_be_bytes([data[index + 2], data[index + 3]]); //Seems like might have an index issue off by one
                    // println!("current index={}",index);
                    // println!("aa={} bb={}",aa,bb);
                    // panic!();
                    // }
                    // assert!(a!=256 && b!=256);
                    label_pointer_set.clear();
                    current_domain_labels.clear();
                    index += 5; //Jump to beginning of next label
                } else {
                    let previous_pointer_label = label_pointer_stack
                        .last()
                        .expect("A pointer exists in the label stack");
                    index = *previous_pointer_label + 2; //Advance from the saved pointer position onto the next label
                    label_pointer_stack.pop(); //maybe special case if there is only one element
                }
                continue;
            }
            //Cycle encountered
            if label_pointer_set.contains(&index) {
                break; //Might want to add some explicit error handling
            }

            if label_is_pointer {
                let offset_position =
                    u16::from_be_bytes([data[index] & 0x3F, data[index + 1]]) as usize;
                label_pointer_stack.push(index);
                label_pointer_set.insert(index);
                index = offset_position;
            } else {
                let label_slice = &data[index + 1..(index + label_octet + 1)];
                current_domain_labels.push(String::from_utf8_lossy(label_slice).to_string());
                index += label_octet + 1; //Jump to beginning of next label
            }
        }
        let bytes_consumed = if question_count == 0 {
            0
        } else {
            index - 12
        };
        (questions_list, bytes_consumed)
    }

    pub fn to_bytes(question: &DNSQuestion) -> Vec<u8> {
        let mut bytes_buffer = Vec::with_capacity(DATAGRAM_HEADER_MAX_SIZE);

        for label in &question.domain_labels {
            bytes_buffer.push((label.len()) as u8);
            bytes_buffer.extend_from_slice(label.as_bytes());
        }
        bytes_buffer.push(0); //Null terminator (Terminates domain name)
        bytes_buffer.extend(question.question_type.to_be_bytes());
        bytes_buffer.extend(question.question_class.to_be_bytes());
        bytes_buffer
    }

    pub fn sequence_to_bytes(question_list: &[DNSQuestion]) -> Vec<u8> {
        question_list
            .iter()
            .flat_map(DNSQuestion::to_bytes)
            .collect()
    }

    pub fn sequence_to_compressed_bytes(question_list: &[DNSQuestion]) -> Vec<u8> {
        let mut bytes_buffer = Vec::with_capacity(DATAGRAM_HEADER_MAX_SIZE);
        let mut labels_map: HashMap<String, u16> = HashMap::with_capacity(CAPACITY_HEURISTIC_BOUND);
        let mut datagram_position = DATAGRAM_HEADER_BYTE_COUNT as u16; //Relative to the entire encoded datagram
        for question in question_list {
            let mut last_index_is_label = true;

            for label in &question.domain_labels {
                if let Some(label_index) = labels_map.get(label) {
                    let label_pointer = 0xC000 | label_index;
                    bytes_buffer.extend(label_pointer.to_be_bytes());
                    datagram_position += 2; //size of u16
                    last_index_is_label = false; //label pointer terminates the question
                    break;
                } else {
                    bytes_buffer.push(label.len() as u8);
                    bytes_buffer.extend_from_slice(label.as_bytes());
                    labels_map.insert(label.clone(), datagram_position);
                    datagram_position += (label.len() + 1) as u16; //Include the byte for storing the length
                }
            }

            //Last index is a label
            if last_index_is_label {
                bytes_buffer.push(0); //Null terminator (Terminates domain name)
                datagram_position += 1;
            }
            bytes_buffer.extend(question.question_type.to_be_bytes());
            bytes_buffer.extend(question.question_class.to_be_bytes());
            datagram_position += 4;
        }
        bytes_buffer
    }

    pub fn print_question(question: &DNSQuestion) {
        println!("DNS Question");
        println!("----------");
        println!("Domain Name");
        println!("{:?}", question.domain_labels);
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
    domain_labels: Vec<String>,
    answer_type: u16,
    answer_class: u16,
    time_to_live: u32,
    length: u16,
    data: Vec<u8>,
}

impl DNSAnswer {
    pub fn from_bytes(data: &[u8]) -> (Vec<DNSAnswer>, usize) {
        let mut answer_list = Vec::with_capacity(CAPACITY_HEURISTIC_BOUND);
        let mut found_domain_labels = Vec::with_capacity(CAPACITY_HEURISTIC_BOUND);
        let mut index = 0;

        while index < data.len() {
            let label_length = data[index] as usize;
            if label_length == 0 {
                if found_domain_labels.is_empty() {
                    break;
                }
                //Might want to add some checks to prevent out of bounds indexing later
                let data_answer_type = u16::from_be_bytes([data[index + 1], data[index + 2]]);
                let data_answer_class = u16::from_be_bytes([data[index + 3], data[index + 4]]);
                let data_ttl = u32::from_be_bytes([
                    data[index + 5],
                    data[index + 6],
                    data[index + 7],
                    data[index + 8],
                ]);
                let data_length = u16::from_be_bytes([data[index + 9], data[index + 10]]);
                let data_buffer = data[index + 11..index + 11 + (data_length as usize)].to_vec();
                answer_list.push(DNSAnswer {
                    domain_labels: found_domain_labels.clone(),
                    answer_type: data_answer_type,
                    answer_class: data_answer_class,
                    time_to_live: data_ttl,
                    length: data_length,
                    data: data_buffer,
                });
                found_domain_labels.clear();
                index += 12 + (data_length as usize); //Jump to beginning of next answer
            } else {
                let label_slice = &data[index + 1..(index + label_length + 1)];
                found_domain_labels.push(String::from_utf8_lossy(label_slice).to_string());
                index += label_length + 1; //Jump to beginning of next label
            }
        }
        let bytes_consumed = if data.is_empty() { 0 } else { index + 1 };
        (answer_list, bytes_consumed)
    }
    pub fn to_bytes(answer: &DNSAnswer) -> Vec<u8> {
        let mut bytes_buffer = Vec::with_capacity(DATAGRAM_HEADER_MAX_SIZE);

        for label in &answer.domain_labels {
            bytes_buffer.push((label.len()) as u8);
            bytes_buffer.extend_from_slice(label.as_bytes());
        }
        bytes_buffer.push(0); //Null terminator (Terminates domain name)
        bytes_buffer.extend(answer.answer_type.to_be_bytes());
        bytes_buffer.extend(answer.answer_class.to_be_bytes());
        bytes_buffer.extend(answer.time_to_live.to_be_bytes());
        bytes_buffer.extend(answer.length.to_be_bytes());
        bytes_buffer.extend_from_slice(&answer.data);
        bytes_buffer
    }

    pub fn sequence_to_bytes(answer_list: &[DNSAnswer]) -> Vec<u8> {
        answer_list.iter().flat_map(DNSAnswer::to_bytes).collect()
    }

    pub fn print_answer(answer: &DNSAnswer) {
        println!("DNS Answer");
        println!("----------");
        println!("Domain Name");
        println!("{:?}", answer.domain_labels);
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
        let mut index = DATAGRAM_HEADER_BYTE_COUNT;
        let message_header = DnsHeader::from_bytes(data[0..12].try_into().unwrap());
        let (message_questions, consumed_question_bytes) = DNSQuestion::from_bytes(data);
        index += consumed_question_bytes;
        // println!("data[{}]={}",index,data[index]);
        let (message_answers, _consumed_answer_bytes) = DNSAnswer::from_bytes(&data[index..]);
        // println!("data {:?}",data);
        DnsMessage {
            header: message_header,
            questions: message_questions,
            answers: message_answers,
            additional: Vec::new(),
        }
    }
    pub fn query_from_bytes(data: &[u8; 512]) -> DnsMessage {
        let data_header: [u8; 12] = data[0..12].try_into().unwrap();
        let dns_header = DnsHeader::from_bytes(&data_header);
        DnsMessage {
            header: dns_header,
            questions: (DNSQuestion::from_bytes(data)).0,
            answers: Vec::new(),
            additional: Vec::new(),
        }
    }

    pub fn to_bytes(message: &DnsMessage) -> ([u8; 512], usize) {
        let header_bytes = DnsHeader::to_bytes(&message.header);
        let num_header_bytes = header_bytes.len();
        let questions_vec_bytes = DNSQuestion::sequence_to_compressed_bytes(&message.questions);
        let answers_vec_bytes = DNSAnswer::sequence_to_bytes(&message.answers);
        let mut message_buffer = [0; 512];
        let mut message_index = 0;
        message_buffer[message_index..message_index + num_header_bytes]
            .copy_from_slice(&header_bytes); //Header fixed at 12 bytes
        message_index += num_header_bytes;
        message_buffer[message_index..message_index + questions_vec_bytes.len()]
            .copy_from_slice(&questions_vec_bytes);
        message_index += questions_vec_bytes.len();
        message_buffer[message_index..message_index + answers_vec_bytes.len()]
            .copy_from_slice(&answers_vec_bytes);
        message_index += answers_vec_bytes.len();
        (message_buffer, message_index)
    }

    fn build_forwarding_header(dns_query_header: &DnsHeader) -> DnsHeader {
        DnsHeader {
            packet_identifer: dns_query_header.packet_identifer,
            is_reply_packet: false,
            operation_code: dns_query_header.operation_code,
            is_authoritative: false,
            is_truncated: dns_query_header.is_truncated,
            recursion_is_desired: dns_query_header.recursion_is_desired,
            recursion_is_available: dns_query_header.recursion_is_available,
            reserved: dns_query_header.reserved,
            response_code: 0,
            question_count: 1,
            answer_record_count: 0,
            authority_record_count: 0,
            additional_record_count: dns_query_header.additional_record_count,
        }
    }

    fn construct_forwarding_message(
        question: &DNSQuestion,
        dns_query_header: &DnsHeader,
    ) -> ([u8; 512], usize) {
        let forwarding_header = DnsMessage::build_forwarding_header(dns_query_header);
        let forwarding_message = DnsMessage {
            header: forwarding_header,
            questions: vec![question.clone()],
            answers: Vec::new(),
            additional: Vec::new(),
        };
        DnsMessage::to_bytes(&forwarding_message)
    }

    fn transmit_forwarding_message(
        fwd_message: &[u8],
        udp_socket: &UdpSocket,
        forwarding_address: &str,
    ) {
        let fwd_bytes = fwd_message.len();
        for _ in 0..MAX_TRANSMISSION_ATTEMPTS {
            match udp_socket.send_to(fwd_message, forwarding_address) {
                Ok(sent_bytes) => {
                    if sent_bytes == fwd_bytes {
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("Error transmitting forwarding data: {}", e);
                    break;
                }
            }
        }
    }

    fn build_response_answer(
        dns_query_header: &DnsHeader,
        question_list: &[DNSQuestion],
        udp_socket: &UdpSocket,
        forwarding_address: &str,
    ) -> Vec<DNSAnswer> {
        // let udp_socket = UdpSocket::bind("127.0.0.1:2054").expect("Failed to bind to address");
        DNSQuestion::print_questions_sequence(question_list);
        println!("In build_response_answer");
        let forwarding_messages: Vec<([u8; 512], usize)> = question_list
            .iter()
            .map(|question| DnsMessage::construct_forwarding_message(question, dns_query_header))
            .collect();

        let mut received_answers = Vec::with_capacity(question_list.len());
        let mut buf = [0; 512];

        for (fwd_message, fwd_bytes) in forwarding_messages {
            DnsMessage::transmit_forwarding_message(
                &fwd_message[0..fwd_bytes],
                udp_socket,
                forwarding_address,
            );
        }
        // println!("question_list.len()={}",question_list.len());
        for _ in 0..question_list.len() {
            match udp_socket.recv_from(&mut buf) {
                Ok((_, _source)) => {
                    //Want to verify the source
                    // println!("Hello friends");
                    // println!("forwarding address")
                    // if source.ip().to_string() != forwarding_address {
                    //     continue;
                    // }
                    let response_message = DnsMessage::from_bytes(&buf);
                    // DnsMessage::print_message(&response_message);
                    let returned_answers=response_message.answers;
                    // println!("returned answers.len()={}",returned_answers.len());
                    received_answers.extend_from_slice(&returned_answers);
                    // println!("received_answers.len()={}",received_answers.len());
                    //Clear the buffer
                    // buf = [0;512];
                    // received_answers.extend(response_message.)
                }
                Err(e) => {
                    eprintln!(
                        "Error attempting to receive data from forwarding server: {}",
                        e
                    );
                }
            }
        }
        received_answers
        // for seq in &received_answers{
        //     DNSAnswer::print_answers_sequence(seq);
        // }
        // // DNSAnswer::print_answers_sequence(received_answers);
        // println!("received_answer.len()={} pre-flatten",received_answers.len());
        // received_answers.into_iter().flatten().collect()
    }

    fn build_response_answer_hardcode(question_list: &[DNSQuestion]) -> Vec<DNSAnswer> {
        question_list
            .iter()
            .map(|question| DNSAnswer {
                domain_labels: question.domain_labels.clone(),
                answer_type: 1,
                answer_class: 1,
                time_to_live: 60,
                length: 4,
                data: vec![8, 8, 8, 8],
            })
            .collect()
    }

    fn build_response_header(dns_query_header: &DnsHeader, acount: u16) -> DnsHeader {
        DnsHeader {
            packet_identifer: dns_query_header.packet_identifer,
            is_reply_packet: true, //Set to true for response packet
            operation_code: dns_query_header.operation_code,
            is_authoritative: dns_query_header.is_authoritative,
            is_truncated: dns_query_header.is_truncated,
            recursion_is_desired: dns_query_header.recursion_is_desired,
            recursion_is_available: false, //Recursion not currently supported
            reserved: dns_query_header.reserved,
            response_code: if dns_query_header.operation_code == 0 {
                0
            } else {
                4
            }, //Only standard query currently supported
            question_count: dns_query_header.question_count,
            answer_record_count: acount,
            authority_record_count: dns_query_header.authority_record_count, //Look into modifying these
            additional_record_count: dns_query_header.additional_record_count, //Looking into modifying these
        }
    }

    pub fn build_response(dns_query: &DnsMessage,udp_socket: &UdpSocket,forwarding_address: &str) -> DnsMessage {
        let response_questions = dns_query.questions.clone();
        DNSQuestion::print_questions_sequence(&response_questions); //Appear to have an issue with storing question type and class
        // let response_answers =DnsMessage::build_response_answer_hardcode(&response_questions);
        let response_answers = DnsMessage::build_response_answer(
            &dns_query.header,
            &response_questions,
            udp_socket,
            forwarding_address,
        );
        // DNSAnswer::print_answers_sequence(&response_answers);
        // println!("response_answer.len() after flatten is {}",response_answers.len());
        // let response_answers = DnsMessage::build_response_answer(
        //     &dns_query.header,
        //     &response_questions,
        //     forwarding_address,
        // );
        let response_additional = dns_query.additional.clone();
        let response_header =
            DnsMessage::build_response_header(&dns_query.header, response_answers.len() as u16);
        DnsMessage {
            header: response_header,
            questions: response_questions,
            answers: response_answers,
            additional: response_additional,
        }
    }

    pub fn response_to_query_bytes(
        query: &[u8; 512],
        udp_socket: &UdpSocket,
        forwarding_address: &str,
    ) -> ([u8; 512], usize) {
        let dns_query_message = DnsMessage::query_from_bytes(query);
        let dns_response_message =
            DnsMessage::build_response(&dns_query_message,udp_socket,forwarding_address);
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

    let command_arguments: Vec<String> = env::args().collect();

    let forwarding_server =
        if command_arguments.len() > 1 && command_arguments[1].as_str() == "--resolver" {
            command_arguments
                .get(2)
                .map(String::as_str)
                .unwrap_or("1.1.1.1")
        } else {
            "1.1.1.1"
        };

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                let (response_buffer, num_encoded_bytes) =
                    DnsMessage::response_to_query_bytes(&buf, &udp_socket,forwarding_server);
                let response = &response_buffer[0..num_encoded_bytes];
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
