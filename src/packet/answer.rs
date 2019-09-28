use crate::error::Error;
use crate::packet::question::Labels;
use crate::packet::question::QuestionType;
use crate::packet::question::QuestionClass;
use crate::MAXIMUM_LABEL_SIZE;
use crate::MAXIMUM_NAMES_SIZE;


// 4.1.3. Resource record format
// https://tools.ietf.org/html/rfc1035#section-4.1.3
// 
// The answer, authority, and additional sections all share the same
// format: a variable number of resource records, where the number of
// records is specified in the corresponding count field in the header.
// Each resource record has the following format:
//                                     1  1  1  1  1  1
//       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                                               |
//     /                                               /
//     /                      NAME                     /
//     |                                               |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                      TYPE                     |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                     CLASS                     |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                      TTL                      |
//     |                                               |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                   RDLENGTH                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
//     /                     RDATA                     /
//     /                                               /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// 
// where:
// 
// NAME            a domain name to which this resource record pertains.
// 
// TYPE            two octets containing one of the RR type codes.  This
//                 field specifies the meaning of the data in the RDATA
//                 field.
// 
// CLASS           two octets which specify the class of the data in the
//                 RDATA field.
// 
// TTL             a 32 bit unsigned integer that specifies the time
//                 interval (in seconds) that the resource record may be
//                 cached before it should be discarded.  Zero values are
//                 interpreted to mean that the RR can only be used for the
//                 transaction in progress, and should not be cached.
// 
// RDLENGTH        an unsigned 16 bit integer that specifies the length in
//                 octets of the RDATA field.
// 
// RDATA           a variable length string of octets that describes the
//                 resource.  The format of this information varies
//                 according to the TYPE and CLASS of the resource record.
//                 For example, the if the TYPE is A and the CLASS is IN,
//                 the RDATA field is a 4 octet ARPA Internet address.

/// 4.1.3. Resource record format
/// The answer, authority, and additional sections all share the same format.
#[derive(PartialEq, Clone)]
pub struct AnswerPacket<T: AsRef<[u8]>> {
    buffer: T
}

impl<T: AsRef<[u8]>> AnswerPacket<T> {

    #[inline]
    pub fn new_unchecked(buffer: T) -> AnswerPacket<T> {
        AnswerPacket { buffer }
    }

    #[inline]
    pub fn new_checked(buffer: T) -> Result<AnswerPacket<T>, Error> {
        let v = Self::new_unchecked(buffer);
        v.check_len()?;

        Ok(v)
    }

    #[inline]
    pub fn check_len(&self) -> Result<(), Error> {
        let data = self.buffer.as_ref();
        let min_size = self.last_label_offset()? + 1 + 2 + 2;
        
        if data.len() < min_size {
            return Err(Error::Truncated);
        }

        Ok(())
    }

    #[inline]
    pub fn into_inner(self) -> T {
        self.buffer
    }

    fn last_label_offset(&self) -> Result<usize, Error> {
        let data = self.buffer.as_ref();

        let mut names_length = 0;
        let mut labels_count = 0;
        let mut idx = 0usize;
        loop {
            if idx >= data.len() {
                return Err(Error::Truncated);
            }

            let len = data[idx] as usize;
            if len == 0 {
                break;
            }

            if len > MAXIMUM_LABEL_SIZE {
                return Err(Error::LabelSizeLimitExceeded);
            }

            let start = idx + 1;

            idx += len + 1;
            labels_count += 1;
            names_length += len;

            let end = idx;
            match &data.get(start..end) {
                Some(s) => {
                    if let Err(_) = std::str::from_utf8(s) {
                        return Err(Error::InvalidUtf8Sequence);
                    }
                },
                None => return Err(Error::Truncated),
            }
        }

        if names_length + labels_count - 1 > MAXIMUM_NAMES_SIZE {
            return Err(Error::NamesSizeLimitExceeded);
        }

        Ok(idx)
    }

    /// two octets containing one of the RR type codes.
    /// This field specifies the meaning of the data in the RDATA field.
    #[inline]
    pub fn atype(&self) -> QuestionType {
        let data = self.buffer.as_ref();

        let offset = self.last_label_offset().unwrap() + 1;
        QuestionType(u16::from_be_bytes([ data[offset + 0], data[offset + 1] ]))
    }

    /// two octets which specify the class of the data in the RDATA field.
    #[inline]
    pub fn aclass(&self) -> QuestionClass {
        let data = self.buffer.as_ref();

        let offset = self.last_label_offset().unwrap() + 1 + 2;
        QuestionClass(u16::from_be_bytes([ data[offset + 0], data[offset + 1] ]))
    }

    /// a 32 bit unsigned integer that specifies the time interval (in seconds) 
    /// that the resource record may be cached before it should be discarded.
    /// Zero values are interpreted to mean that the RR can only be used for the
    /// transaction in progress, and should not be cached.
    #[inline]
    pub fn ttl(&self) -> u32 {
        let data = self.buffer.as_ref();

        let offset = self.last_label_offset().unwrap() + 1 + 2 + 2;
        u32::from_be_bytes([ data[offset+0], data[offset+1], data[offset+2], data[offset+3] ])
    }

    /// an unsigned 16 bit integer that specifies the length in octets of the RDATA field.
    #[inline]
    pub fn rdlen(&self) -> u16 {
        let data = self.buffer.as_ref();

        let offset = self.last_label_offset().unwrap() + 1 + 2 + 2 + 4;
        u16::from_be_bytes([ data[offset + 0], data[offset + 1] ])
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> AnswerPacket<&'a T> {
    /// Name of the node to which this record pertains
    #[inline]
    pub fn labels(&self) -> Labels<'a> {
        let offset = self.last_label_offset().unwrap() + 1;
        let data = self.buffer.as_ref();
        Labels {
            offset: 0,
            data: &data[..offset],
        }
    }

    /// Additional RR-specific data
    #[inline]
    pub fn rdata(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();

        let offset = self.last_label_offset().unwrap() + 1 + 2 + 2 + 4 + 2;
        &data[offset..self.rdlen() as usize]
    }

    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();

        let offset = self.last_label_offset().unwrap() + 1 + 2 + 2 + 4 + 2 + self.rdlen() as usize;
        &data[offset..]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AnswerPacket<T> {
    #[inline]
    pub fn set_names(&mut self, value: &str) {
        assert!(value.len() <= MAXIMUM_NAMES_SIZE);
        let data = self.buffer.as_mut();

        let mut offset = 0usize;
        for label in value.split('.') {
            assert!(label.len() <= MAXIMUM_LABEL_SIZE);

            data[offset] = label.len() as u8;
            let start = offset + 1;
            let end = start + label.len();

            &mut data[start..end].copy_from_slice(label.as_bytes());
            offset += 1 + label.len();
        }

        if data[offset] != 0 {
            data[offset] = 0;
        }
    }

    #[inline]
    pub fn set_atype(&mut self, value: QuestionType) {
        let offset = self.last_label_offset().unwrap() + 1;
        let data = self.buffer.as_mut();
        let octets = value.0.to_be_bytes();

        // NOTE: 确保名字先存储了！
        assert_eq!(data[offset-1], 0);

        data[offset + 0] = octets[0];
        data[offset + 1] = octets[1];
    }

    #[inline]
    pub fn set_aclass(&mut self, value: QuestionClass) {
        let offset = self.last_label_offset().unwrap() + 1 + 2;
        let data = self.buffer.as_mut();
        let octets = value.0.to_be_bytes();

        // NOTE: 确保名字先存储了！
        assert_eq!(data[offset-3], 0);

        data[offset + 0] = octets[0];
        data[offset + 1] = octets[1];
    }


    #[inline]
    pub fn set_ttl(&mut self, value: u32) {
        let offset = self.last_label_offset().unwrap() + 1 + 2 + 2;
        let data = self.buffer.as_mut();
        let octets = value.to_be_bytes();

        // NOTE: 确保名字先存储了！
        assert_eq!(data[offset-5], 0);

        data[offset + 0] = octets[0];
        data[offset + 1] = octets[1];
        data[offset + 2] = octets[2];
        data[offset + 3] = octets[3];
    }

    #[inline]
    pub fn set_rdlen(&mut self, value: u16) {
        let offset = self.last_label_offset().unwrap() + 1 + 2 + 2 + 4;
        let data = self.buffer.as_mut();
        let octets = value.to_be_bytes();

        // NOTE: 确保名字先存储了！
        assert_eq!(data[offset-9], 0);

        data[offset + 0] = octets[0];
        data[offset + 1] = octets[1];
    }

    #[inline]
    pub fn rdata_mut(&mut self) -> &mut [u8] {
        let offset = self.last_label_offset().unwrap() + 1 + 2 + 2 + 4 + 2;
        let rdlen = self.rdlen() as usize;
        let data = self.buffer.as_mut();
        
        // NOTE: 确保名字先存储了！
        assert_eq!(data[offset-11], 0);
        
        &mut data[offset..rdlen]
    }

    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8]{
        let offset = self.last_label_offset().unwrap() + 1 + 2 + 2 + 4 + 2 + self.rdlen() as usize;
        let data = self.buffer.as_mut();
        
        &mut data[offset..]
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> std::fmt::Debug for AnswerPacket<&'a T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AnswerPacket {{ labels: {:?}, atype: {:?}, aclass: {:?}, ttl: {:?}, rdlen: {:?}, rdata: {:?} }}",
                self.labels().collect::<Vec<&str>>(),
                self.atype(),
                self.aclass(),
                self.ttl(),
                self.rdlen(),
                self.rdata(),
        )
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> std::fmt::Display for AnswerPacket<&'a T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AnswerPacket {{ labels: {:?}, atype: {}, aclass: {}, ttl: {}, rdlen: {}, rdata: {:?} }}",
                self.labels().collect::<Vec<&str>>(),
                self.atype(),
                self.aclass(),
                self.ttl(),
                self.rdlen(),
                self.rdata(),
        )
    }
}


