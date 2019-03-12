use gssapi_krb5_sys;
use std::error;
use std::fmt;
use std::result;
use std::str;
use super::buffer::Buffer;
use super::oid::OID;

pub type Result<T> = result::Result<T, Error>;

pub struct Error {
    major_status: u32,
    minor_status: u32,
    mech_type: OID,
}

impl Error {
    pub fn new(major_status: u32, minor_status: u32, mech_type: OID) -> Self {
        Error {
            major_status: major_status,
            minor_status: minor_status,
            mech_type: mech_type,
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "GSSAPI Error"
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "GSS Error({}, {}): ", self.major_status, self.minor_status)?;
        let mut first = true;

        for status in DisplayStatus::new(self.major_status,
                                         gssapi_krb5_sys::GSS_C_GSS_CODE,
                                         &self.mech_type) {
            if !first {
                write!(f, " -- ")?;
            }
            first = false;

            write!(f, "{}", str::from_utf8(&status).unwrap())?;
        }

        for status in DisplayStatus::new(self.minor_status,
                                         gssapi_krb5_sys::GSS_C_MECH_CODE,
                                         &self.mech_type) {
            if !first {
                write!(f, " -- ")?;
            }
            first = false;

            write!(f, "{}", str::from_utf8(&status).unwrap())?;
        }

        Ok(())
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

struct DisplayStatus<'a> {
    code: u32,
    status_type: i32,
    mech_type: &'a OID,
    message_context: u32,
    done: bool
}

impl<'a> DisplayStatus<'a> {
    fn new(code: u32, status_type: u32, mech_type: &'a OID) -> Self {
        DisplayStatus {
            code: code,
            status_type: status_type as i32,
            mech_type: mech_type,
            message_context: 0,
            done: false,
        }
    }
}

impl<'a> Iterator for DisplayStatus<'a> {
    type Item = Buffer;

    fn next(&mut self) -> Option<Buffer> {
        if self.done {
            None
        } else {
            let mut minor_status = 0;
            let mut status_string = Buffer::new();

            let major_status = unsafe {
                gssapi_krb5_sys::gss_display_status(
                    &mut minor_status,
                    self.code,
                    self.status_type,
                    self.mech_type.get_handle(),
                    &mut self.message_context,
                    status_string.get_handle(),
                )
            };

            if major_status == gssapi_krb5_sys::GSS_S_COMPLETE {
                self.done = self.message_context == 0;
                Some(status_string)
            } else {
                panic!("failed to stringify error message");
            }
        }
    }
}
