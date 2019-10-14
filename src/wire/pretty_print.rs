use crate::error::Error;
use crate::wire;

const EMPTY: &str = "";


#[inline]
pub fn pretty_print(ident: usize, buffer: &[u8]) {
    if let Err(e) = pprint(ident, buffer) {
        println!("{:?}", e);
    }
}

// 🔐🔒🔓🔑🗝 ❤️🧡💛💚💙💜🖤💔❣️ ✅❌❗️❕❓❔‼️⁉️❎✔️
// 🔜⚠️🔏📍📌📝📑📄📃📜🔍🔎🗺🚧⚓️✍️🌏🌍🌎🌐📧📨📩✉️📤📪📫📬📭📮

fn print_record_packet(ident: usize,
                       buffer: &[u8],
                       offset: &mut usize,
                       name: &mut String,
                       header_rcode: &mut wire::ResponseCode,
                       opt_record_count: &mut usize,
                       dnssec_ok: &mut bool,
                       is_query: bool) -> Result<(), Error> {
    // resource record packet
    if name.len() > 0 {
        name.clear();
    }

    let amt = wire::read_name(*offset, &buffer, name, 0)?;
    *offset += amt;

    let rr = wire::RecordPacket::new_checked(&buffer[*offset..])?;
    let kind = rr.kind();
    if kind == wire::Kind::OPT {
        if name != "" {
            // Name must be empty (root).
            return Err(Error::Unrecognized);
        }

        if *opt_record_count > 0 {
            // dns message can only contain 1 OPT Resource Record
            return Err(Error::Unrecognized);
        }

        let ext_rr = wire::ExtensionPacket::new_checked(&buffer[*offset..])?;
        let udp_size = ext_rr.udp_size();
        let ext_rcode = ext_rr.rcode();
        let ext_version = ext_rr.version();
        let ext_flags = ext_rr.flags();
        let rdlen = ext_rr.rdlen();
        let rdata = ext_rr.rdata();

        if ext_flags.do_() {
            *dnssec_ok = true;
        }

        let ecs = if rdlen == 0 {
            None
        } else {
            let opt_data = wire::ExtensionDataPacket::new_checked(rdata)?;
            let opt_code = opt_data.option_code();
            let opt_length = opt_data.option_length();
            let ecs = if opt_code == wire::OptionCode::EDNS_CLIENT_SUBNET {
                Some(wire::ClientSubnetPacket::new_checked(opt_data.option_data())?)
            } else {
                None
            };

            ecs
        };

        let opt_rr_icon = match (is_query, *dnssec_ok, ecs.is_some()) {
            (true, true, true) => "📃🔏📌",
            (true, true, false) => "📃🔏",
            (true, false, true) => "📃📌",
            (true, false, false) => "📃",
            (false, false, false) => "📃",
            (false, false, true) => "📃📍",
            (false, true, true) => "📃🔏📍",
            (false, true, false) => "📃🔏",
        };

        print!("{:ident$}{} Name=. Kind={} UdpSize={} EXT_RCODE={} EXT_VER={} EXT_FLAGS={:?}",
            EMPTY, opt_rr_icon, kind, udp_size, ext_rcode, ext_version, ext_flags, ident = ident);

        if let Some(ecs) = ecs {
            if is_query {
                println!(" CLIENT-SUBNET: {}/{}", ecs.address(), ecs.src_prefixlen())
            } else {
                println!(" CLIENT-SUBNET: {}/{}", ecs.address(), ecs.scope_prefixlen())
            }
        } else {
            println!();
        }
        
        if ext_rcode > 0 {
            // The original header flags has been extended.
            let new_header_rcode = wire::ResponseCode::new(((ext_rcode as u16) << 8) | header_rcode.code());
            println!("{:ident$}⚠️  The original header rcode has been extended: {} --> {}",
                EMPTY, header_rcode, new_header_rcode, ident = ident);
            *header_rcode = new_header_rcode;
        }
        
        *offset += rdlen as usize;
    } else {
        let class = rr.class();
        let ttl = rr.ttl();
        let rdlen = rr.rdlen();
        let rdata = rr.rdata();

        *offset += rr.header_len();

        let value = wire::Record::parse(*offset, &buffer, kind, class, rdata)?;
        
        println!("{:ident$}📃 Name={} Kind={} Class={} TTL={} Value={}",
            EMPTY, name, kind, class, ttl, value, ident = ident);

        *offset += rdlen as usize;
    }

    Ok(())
}

fn pprint(ident: usize, buffer: &[u8]) -> Result<(), Error> {
    let mut offset = 0usize;
    let mut name = String::new();

    let hdr = wire::HeaderPacket::new_checked(buffer)?;
    let id = hdr.id();
    
    let flags = hdr.flags();
    let is_query = !flags.qr();
    let mut rcode = flags.rcode();
    let mut dnssec_ok = false;

    let msg_kind = if is_query { "📧" } else { "📨" };

    // |QR|   Opcode  |AA|TC|RD|RA|AD|CD|Z|   RCODE   |
    println!("{:ident$}{} ID={} QR={} OPCODE={} AA={} TC={} RD={} RA={} AD={} CD={} Z={} RCODE={}",
        EMPTY,
        msg_kind,
        id,
        flags.qr(),
        flags.opcode(),
        flags.aa(),
        flags.tc(),
        flags.rd(),
        flags.ra(),
        flags.ad(),
        flags.cd(),
        flags.z(),
        rcode,
        ident = ident);

    let qdcount = hdr.qdcount();
    let ancount = hdr.ancount();
    let nscount = hdr.nscount();
    let arcount = hdr.arcount();

    println!("{:ident$}qdcount={} ancount={} nscount={} arcount={}",
        EMPTY, qdcount, ancount, nscount, arcount, ident = ident + 3);
    offset += hdr.len();

    if rcode.is_err() {
        return Ok(())
    }

    // Question Section
    for _ in 0..qdcount {
        name.clear();
        let amt = wire::read_name(offset, &buffer, &mut name, 0)?;
        offset += amt;

        let question = wire::QuestionPacket::new_checked(&buffer[offset..])?;
        offset += question.len();

        println!("{:ident$}🔎 Name={} Kind={} Class={}",
            EMPTY, name, question.kind(), question.class(), ident = ident);
    }

    let mut opt_record_count = 0usize;
    for _ in 0..ancount {
        // Answer Section
        print_record_packet(ident, buffer, &mut offset, &mut name, &mut rcode, &mut opt_record_count, &mut dnssec_ok, is_query)?;
    }
    
    for _ in 0..nscount {
        // Authority Records Section
        print_record_packet(ident, buffer, &mut offset, &mut name, &mut rcode, &mut opt_record_count, &mut dnssec_ok, is_query)?;
    }

    for _ in 0..arcount {
        // Additional Records Section
        print_record_packet(ident, buffer, &mut offset, &mut name, &mut rcode, &mut opt_record_count, &mut dnssec_ok, is_query)?;
    }

    Ok(())
}
