use gssapi_krb5_sys;
use std::ffi::{CStr, CString};
use std::marker::PhantomData;
use std::ops;
use std::os::raw::c_void;
use std::ptr;
use std::slice;

#[derive(Debug)]
pub struct Buffer {
    buffer_desc: gssapi_krb5_sys::gss_buffer_desc,
}

impl Buffer {
    pub fn new() -> Self {
        Buffer {
            buffer_desc: gssapi_krb5_sys::gss_buffer_desc {
                length: 0,
                value: ptr::null_mut(),
            }
        }
    }

    pub unsafe fn get_handle(&mut self) -> gssapi_krb5_sys::gss_buffer_t {
        &mut self.buffer_desc
    }

    pub fn as_base64(&self) -> String {
        data_encoding::BASE64.encode(&self)
    }

    pub fn from_base64(s: &str) -> Result<Self, ()> {
        data_encoding::BASE64.decode(s.as_bytes()).map_err(|_| ())
            .map(Buffer::from)
    }

    pub fn to_option(self) -> Option<Buffer> {
        if self.buffer_desc.length == 0 || self.buffer_desc.value.is_null() {
            None
        } else {
            Some(self)
        }
    }
}

impl std::fmt::Display for Buffer {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = String::from_utf8(self.to_vec()).map_err(|e| { println!("{:?}", e); std::fmt::Error })?;
        write!(f, "{}", s)
    }
}


impl core::str::FromStr for Buffer {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        // let s = s.as_bytes().to_vec();
        Ok(Buffer {
            buffer_desc: gssapi_krb5_sys::gss_buffer_desc {
                length: s.len(),
                value: CString::new(s).unwrap().into_raw() as *mut std::ffi::c_void,
            }
        })
    }
}

impl From<Vec<u8>> for Buffer {
    fn from(other: Vec<u8>) -> Self {
        Buffer {
            buffer_desc: gssapi_krb5_sys::gss_buffer_desc {
                length: other.len(),
                value: Box::into_raw(other.into_boxed_slice()) as *mut std::ffi::c_void,
            }
        }
    }
}

impl From<Buffer> for String {
    fn from(other: Buffer) -> String {
        let length = other.buffer_desc.length;
        let value = other.buffer_desc.value;

        if length == 0 || value.is_null() {
            String::new()
        } else {
            unsafe {
                CStr::from_ptr(value as *mut i8).to_str().expect("invalid string").to_string()
            }
        }
    }
}

impl From<Buffer> for Vec<u8> {
    fn from(other: Buffer) -> Vec<u8> {
        let length = other.buffer_desc.length;
        let value = other.buffer_desc.value;

        if length == 0 || value.is_null() {
            Vec::new()
        } else {
            // let slice: &[u8] = unsafe {
            //     std::slice::from_raw_parts(value as *const u8, length)
            // };
            other.to_vec()
        }
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        let mut min_stat = 0;
        let maj_stat = unsafe {
            gssapi_krb5_sys::gss_release_buffer(&mut min_stat, &mut self.buffer_desc)
        };

        if maj_stat != gssapi_krb5_sys::GSS_S_COMPLETE {
            panic!("failed to release buffer");
        }
    }
}

impl Default for Buffer {
    fn default() -> Self {
        Buffer::new()
    }
}

impl ops::Deref for Buffer {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self.buffer_desc.value as *const u8,
                self.buffer_desc.length)
        }
    }
}

pub struct BufferRef<'a> {
    buffer_desc: gssapi_krb5_sys::gss_buffer_desc,
    _phantom: PhantomData<&'a u8>,
}

impl<'a> BufferRef<'a> {
    pub fn new(buffer: &[u8]) -> Self {
        BufferRef {
            buffer_desc: gssapi_krb5_sys::gss_buffer_desc {
                length: buffer.len(),
                value: buffer.as_ptr() as *mut c_void,
            },
            _phantom: PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        self.buffer_desc.length
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub unsafe fn get_handle(&mut self) -> gssapi_krb5_sys::gss_buffer_t {
        &mut self.buffer_desc
    }
}

impl<'a> From<&'a Vec<u8>> for BufferRef<'a> {
    fn from(buffer: &'a Vec<u8>) -> Self {
        BufferRef::new(&**buffer)
    }
}

impl<'a> From<&'a [u8]> for BufferRef<'a> {
    fn from(buffer: &'a [u8]) -> Self {
        BufferRef::new(buffer)
    }
}

impl<'a> From<&'a String> for BufferRef<'a> {
    fn from(buffer: &'a String) -> Self {
        BufferRef::new(buffer.as_bytes())
    }
}

impl<'a> From<&'a str> for BufferRef<'a> {
    fn from(buffer: &'a str) -> Self {
        BufferRef::new(buffer.as_bytes())
    }
}

impl<'a> From<&'a Buffer> for BufferRef<'a> {
    fn from(buffer: &'a Buffer) -> Self {
        BufferRef {
            buffer_desc: gssapi_krb5_sys::gss_buffer_desc {
                length: buffer.buffer_desc.length,
                value: buffer.buffer_desc.value,
            },
            _phantom: PhantomData,
        }
    }
}

