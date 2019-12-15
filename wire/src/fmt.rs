use crate::error::Error;
use crate::error::ErrorKind;

use chrono;


const DNS_DATETIME_FORMAT: &str = "%Y%m%d%H%M%S";

pub trait Base64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;
}

pub trait DateTimeFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;
}

// use std::fmt::Display ?
pub trait Presentation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;
}

pub trait FromPresentation: Sized {
    type Err;

    fn from_presentation(s: &str) -> Result<Self, Self::Err>;
}


// 1573557530 --> "20191026050000"
pub fn timestamp_to_datetime(timestamp: u32) -> String {
    let native_dt = chrono::NaiveDateTime::from_timestamp(timestamp as i64, 0);
    let datetime = chrono::DateTime::<chrono::Utc>::from_utc(native_dt, chrono::Utc);
    format!("{}", datetime.format(DNS_DATETIME_FORMAT))
}

// "20191026050000" --> 1573557530
pub fn datetime_to_timestamp(s: &str) -> Result<u32, Error> {
    let timestamp: i64 = chrono::TimeZone::datetime_from_str(&chrono::Utc, s, DNS_DATETIME_FORMAT)
        .map_err(|_| Error::from(ErrorKind::FormatError))?
        .timestamp();
    
    if timestamp < 0 || timestamp > std::u32::MAX as i64 {
        return Err(Error::from(ErrorKind::FormatError));
    }
    
    let timestamp = timestamp as u32;
    
    Ok(timestamp)
}
