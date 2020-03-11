
use base64;


const URI_PATH: &str      = "/dns-query";
const CONTENT_TYPE: &str  = "application/dns-message";
const DNS_QUERY_KEY: &str = "dns";
const DNS_MSG_ID: u16     = 0; // Alwasy set 0.


pub fn base64url_decode<T: AsRef<[u8]> + ?Sized>(input: &T) -> Result<Vec<u8>, base64::DecodeError> {
    base64::decode_config(input, base64::URL_SAFE_NO_PAD)
}

pub fn base64url_encode<T: AsRef<[u8]> + ?Sized>(input: &T) -> String {
    base64::encode_config(input, base64::URL_SAFE_NO_PAD)
}


pub mod server;
pub mod client;
