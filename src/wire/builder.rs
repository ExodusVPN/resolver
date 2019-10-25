use crate::wire;
use crate::error::Error;

use std::net::IpAddr;
use std::collections::HashMap;

// Domain Names - Implementation and Specification
// https://tools.ietf.org/html/rfc883

bitflags! {
    pub struct ReprFlags: u8 {
        const QR = 0b_1000_0000; // Response
        const AA = 0b_0100_0000; // Authoritative Answer
        const TC = 0b_0010_0000; // TrunCation
        const RD = 0b_0001_0000; // Recursion Desired
        const RA = 0b_0000_1000; // Recursion Available
        const DO = 0b_0000_0100; // DNSSEC OK
        const AD = 0b_0000_0010; // Authentic Data    RFC4035, RFC6840, RFC Errata 4924
        const CD = 0b_0000_0001; // Checking Disabled RFC4035, RFC6840, RFC Errata 4927
    }
}

impl ReprFlags {
    pub fn new_unchecked(bits: u8) -> Self {
        unsafe {
            Self::from_bits_unchecked(bits)
        }
    }
    
    #[inline]
    pub fn to_header_flags(&self) -> wire::Flags {
        let mut flags = wire::Flags::empty();
        
        if self.contains(Self::QR) {
            flags |= wire::Flags::QR_RES;
        }

        if self.contains(Self::AA) {
            flags |= wire::Flags::AA;
        }

        if self.contains(Self::TC) {
            flags |= wire::Flags::TC;
        }

        if self.contains(Self::RD) {
            flags |= wire::Flags::RD;
        }

        if self.contains(Self::RA) {
            flags |= wire::Flags::RA;
        }

        if self.contains(Self::AD) {
            flags |= wire::Flags::AD;
        }

        if self.contains(Self::CD) {
            flags |= wire::Flags::CD;
        }

        flags
    }

    #[inline]
    pub fn from_header_flags(header_flags: &wire::Flags) -> Self {
        let mut flags = Self::empty();
        if header_flags.qr() {
            flags |= ReprFlags::QR;
        }
        if header_flags.aa() {
            flags |= ReprFlags::AA;
        }
        if header_flags.tc() {
            flags |= ReprFlags::TC;
        }
        if header_flags.rd() {
            flags |= ReprFlags::RD;
        }
        if header_flags.ra() {
            flags |= ReprFlags::RA;
        }
        if header_flags.ad() {
            flags |= ReprFlags::AD;
        }
        if header_flags.cd() {
            flags |= ReprFlags::CD;
        }

        flags
    }
}

impl Default for ReprFlags {
    fn default() -> Self {
        Self::RD | Self::DO
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Question {
    pub name: String,
    pub kind: wire::Kind,
    pub class: wire::Class,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Request {
    pub id: u16,
    pub flags: ReprFlags,     // u8
    pub opcode: wire::OpCode, // u8
    pub client_subnet: Option<wire::ClientSubnet>,
    pub question: Question,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Response {
    pub id: u16,
    pub flags: ReprFlags, // u8
    pub opcode: wire::OpCode,
    pub rcode: wire::ResponseCode,
    pub client_subnet: Option<wire::ClientSubnet>,
    pub question: Question,
    pub answers: Vec<wire::Record>,
    pub authorities: Vec<wire::Record>,
    pub additionals: Vec<wire::Record>,
}

impl Request {
    pub fn pretty_print(&self) {
        println!("ID={} OPCODE={:?} FLAGS={:?} CLIENT-SUBNET={}",
            self.id,
            self.opcode,
            self.flags,
            match &self.client_subnet {
                Some(ecs) => format!("{}", ecs),
                None => format!("N/A"),
            },
        );

        println!("Question Section:");
        println!("\t{:?}", self.question);
    }

    pub fn parse(buffer: &[u8]) -> Result<Self, Error> {
        let mut offset = 0usize;

        let hdr = wire::HeaderPacket::new_checked(buffer)?;
        let id = hdr.id();
        
        let header_flags = hdr.flags();
        let mut flags = ReprFlags::from_header_flags(&header_flags);
        
        let opcode = header_flags.opcode();
        let mut rcode = header_flags.rcode();

        let qdcount = hdr.qdcount();
        let ancount = hdr.ancount();
        let nscount = hdr.nscount();
        let arcount = hdr.arcount();

        if qdcount == 0 {
            return Err(Error::Unrecognized);
        }

        offset += hdr.len();

        let mut question = None;
        let mut opt_record: Option<wire::OPT> = None;
        let mut client_subnet = None;

        for idx in 0..qdcount {
            // Question
            let mut name = String::new();
            let amt = wire::read_name(offset, &buffer, &mut name, 0)?;
            offset += amt;

            let question_pkt = wire::QuestionPacket::new_checked(&buffer[offset..])?;
            offset += question_pkt.len();

            if idx == 0 {
                question = Some(Question {
                    name: name,
                    kind: question_pkt.kind(),
                    class: question_pkt.class(),
                });
            }
        }

        let question = question.unwrap();

        for _ in 0..ancount {
            // Answer
            let mut name = String::new();
            let amt = wire::read_name(offset, &buffer, &mut name, 0)?;
            offset += amt;

            let rr = wire::RecordPacket::new_checked(&buffer[offset..])?;
            let rdlen = rr.rdlen();

            offset += rr.total_len();
        }

        for _ in 0..nscount {
            // Authority
            let mut name = String::new();
            let amt = wire::read_name(offset, &buffer, &mut name, 0)?;
            offset += amt;

            let rr = wire::RecordPacket::new_checked(&buffer[offset..])?;
            let rdlen = rr.rdlen();

            offset += rr.total_len();
        }

        for _ in 0..arcount {
            // Additional
            match wire::deserialize_record(&mut offset, &buffer)? {
                Some(wire::AnyRecord::Pseudo(wire::PseudoRecord::OPT(opt))) => {
                    if opt_record.is_some() {
                        debug!("dns message can only contain 1 OPT Resource Record");
                        return Err(Error::Unrecognized);
                    }
                    opt_record = Some(opt);
                },
                _ => {

                },
            }
        }

        if let Some(opt) = opt_record {
            if opt.flags.do_() {
                // DNSSEC OK.
                flags |= ReprFlags::DO;
            }

            if opt.rcode > 0 {
                rcode.extend_hi(opt.rcode);
            }

            match opt.value {
                wire::OptValue::ECS(ecs) => {
                    client_subnet = Some(ecs);
                },
                _ => { }
            }
        }

        Ok(Request {
            id,
            flags,
            opcode,
            client_subnet,
            question,
        })
    }

    pub fn serialize(&self, buffer: &mut [u8]) -> Result<usize, Error> {
        let mut name_dict: HashMap<u64, u16> = HashMap::new();
        let mut offset = 0usize;

        let mut flags = self.flags.to_header_flags();
        flags.set_opcode(self.opcode);
        flags.set_rcode(wire::ResponseCode::OK);

        let mut hdr = wire::HeaderPacket::new_unchecked(&mut buffer[..]);
        hdr.set_id(self.id);
        hdr.set_flags(flags);
        hdr.set_qdcount(1);
        hdr.set_ancount(0);
        hdr.set_nscount(0);
        hdr.set_arcount(1);

        offset += hdr.len();

        let amt = wire::write_name(&self.question.name, offset, &mut buffer[..], &mut name_dict)?;
        offset += amt;

        let mut pkt = wire::QuestionPacket::new_unchecked(&mut buffer[offset..]);
        pkt.set_kind(self.question.kind);
        pkt.set_class(self.question.class);

        offset += pkt.len();

        match &self.client_subnet {
            Some(ecs) => {
                let amt = wire::write_dnssec_and_ecs(offset, &mut buffer[..], ecs.address, ecs.src_prefix_len)?;
                offset += amt;
            },
            None => {
                let amt = wire::write_dnssec(offset, &mut buffer[..])?;
                offset += amt;
            },
        }

        Ok(offset)
    }
}

impl Response {
    pub fn pretty_print(&self) {
        println!("ID={} OPCODE={:?} RCODE={:?} FLAGS={:?} CLIENT-SUBNET={}",
            self.id,
            self.opcode,
            self.rcode,
            self.flags,
            match &self.client_subnet {
                Some(ecs) => format!("{}", ecs),
                None => format!("N/A"),
            },
        );

        println!("Question Section:");
        println!("\t{:?}", self.question);

        println!("Answer Section:");
        for answer in self.answers.iter() {
            println!("\t{:?}", answer);
        }
        println!("Authority Section:");
        for authority in self.authorities.iter() {
            println!("\t{:?}", authority);
        }
        println!("Additional Section:");
        for additional in self.additionals.iter() {
            println!("\t{:?}", additional);
        }
    }

    pub fn parse(buffer: &[u8]) -> Result<Self, Error> {
        let mut offset = 0usize;

        let hdr = wire::HeaderPacket::new_checked(buffer)?;
        let id = hdr.id();
        
        let header_flags = hdr.flags();
        let mut flags = ReprFlags::from_header_flags(&header_flags);
        
        let opcode = header_flags.opcode();
        let mut rcode = header_flags.rcode();

        let qdcount = hdr.qdcount();
        let ancount = hdr.ancount();
        let nscount = hdr.nscount();
        let arcount = hdr.arcount();

        if qdcount == 0 {
            return Err(Error::Unrecognized);
        }

        offset += hdr.len();

        let mut question = None;
        let mut answers = Vec::new();
        let mut authorities = Vec::new();
        let mut additionals = Vec::new();
        let mut opt_record: Option<wire::OPT> = None;
        let mut client_subnet = None;

        for idx in 0..qdcount {
            // Question
            let mut name = String::new();
            let amt = wire::read_name(offset, &buffer, &mut name, 0)?;
            offset += amt;

            let question_pkt = wire::QuestionPacket::new_checked(&buffer[offset..])?;
            offset += question_pkt.len();

            if idx == 0 {
                question = Some(Question {
                    name: name,
                    kind: question_pkt.kind(),
                    class: question_pkt.class(),
                });
            }
        }

        let question = question.unwrap();

        for _ in 0..ancount {
            // Answer
            match wire::deserialize_record(&mut offset, &buffer)? {
                Some(wire::AnyRecord::Normal(record)) => {
                    answers.push(record);
                },
                _ => { }
            }
        }

        for _ in 0..nscount {
            // Authority
            match wire::deserialize_record(&mut offset, &buffer)? {
                Some(wire::AnyRecord::Normal(record)) => {
                    authorities.push(record);
                },
                _ => { }
            }
        }

        for _ in 0..arcount {
            // Additional
            match wire::deserialize_record(&mut offset, &buffer)? {
                Some(wire::AnyRecord::Pseudo(wire::PseudoRecord::OPT(opt))) => {
                    if opt_record.is_some() {
                        debug!("dns message can only contain 1 OPT Resource Record");
                        return Err(Error::Unrecognized);
                    }
                    opt_record = Some(opt);
                },
                Some(wire::AnyRecord::Normal(record)) => {
                    additionals.push(record);
                },
                _ => { },
            }
        }

        if let Some(opt) = opt_record {
            if opt.flags.do_() {
                // DNSSEC OK.
                flags |= ReprFlags::DO;
            }

            if opt.rcode > 0 {
                rcode.extend_hi(opt.rcode);
            }

            match opt.value {
                wire::OptValue::ECS(ecs) => {
                    client_subnet = Some(ecs);
                },
                _ => { }
            }
        }

        Ok(Response {
            id,
            flags,
            opcode,
            rcode,
            client_subnet,
            question,
            answers,
            authorities,
            additionals,
        })
    }

    pub fn serialize(&self, buffer: &mut [u8]) -> Result<usize, Error> {
        let mut name_dict: HashMap<u64, u16> = HashMap::new();
        let mut offset = 0usize;

        let mut flags = self.flags.to_header_flags();
        flags.set_opcode(self.opcode);
        flags.set_rcode(self.rcode);

        let ancount = self.answers.len() as u16;
        let nscount = self.authorities.len() as u16;
        let arcount = self.additionals.len() as u16;

        let mut hdr = wire::HeaderPacket::new_unchecked(&mut buffer[..]);
        hdr.set_id(self.id);
        hdr.set_flags(flags);
        hdr.set_qdcount(1);
        hdr.set_ancount(ancount);
        hdr.set_nscount(nscount);
        hdr.set_arcount(arcount + 1);
        
        offset += hdr.len();
        
        // Question
        let amt = wire::write_name(&self.question.name, offset, &mut buffer[..], &mut name_dict)?;
        offset += amt;
        let mut pkt = wire::QuestionPacket::new_unchecked(&mut buffer[offset..]);
        pkt.set_kind(self.question.kind);
        pkt.set_class(self.question.class);
        offset += pkt.len();

        for idx in 0..ancount {
            // Answer
            let record = &self.answers[idx as usize];
            record.serialize(&mut offset, &mut name_dict, buffer)?;
        }

        for idx in 0..nscount {
            // Authority
            let record = &self.answers[idx as usize];
            record.serialize(&mut offset, &mut name_dict, buffer)?;
        }

        for idx in 0..arcount {
            // Additional
            let record = &self.answers[idx as usize];
            record.serialize(&mut offset, &mut name_dict, buffer)?;
        }

        match &self.client_subnet {
            Some(ecs) => {
                let amt = wire::write_dnssec_and_ecs(offset, &mut buffer[..], ecs.address, ecs.src_prefix_len)?;
                offset += amt;
            },
            None => {
                let amt = wire::write_dnssec(offset, &mut buffer[..])?;
                offset += amt;
            },
        }

        Ok(offset)
    }
}

