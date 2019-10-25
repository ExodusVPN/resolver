use crate::wire;

use base64;


#[derive(PartialEq, Eq, Clone)]
pub struct Digest<T: AsRef<[u8]>> {
    inner: T
}

impl<T: AsRef<[u8]>> Digest<T> {
    #[inline]
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_ref()
    }

    #[inline]
    pub fn into_inner(self) -> T {
        self.inner
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }
    
    #[inline]
    pub fn hexdigest(&self) -> String {
        let digest = self.inner.as_ref();
        let mut s = String::from("0x");
        for n in digest.iter() {
            s.push_str(format!("{:02x}", n).as_ref());
        }
        s
    }

    #[inline]
    pub fn base64_string(&self) -> String {
        let digest = self.inner.as_ref();

        base64::encode(digest)
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Digest<T> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<T: AsRef<[u8]>> std::fmt::Debug for Digest<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.hexdigest())
    }
}

impl<T: AsRef<[u8]>> std::fmt::Display for Digest<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.base64_string())
    }
}