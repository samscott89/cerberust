use gssapi_krb5_sys;
use std::ptr;
use super::buffer::{Buffer, BufferRef};
use super::error::{Error, Result};
use super::oid::OID;

#[derive(Debug)]
pub struct Name {
    name: gssapi_krb5_sys::gss_name_t,
    name_type: OID,
}

impl Name {
    pub fn new<'a, T: Into<BufferRef<'a>>>(name: T, name_type: OID) -> Result<Self> {
        let mut name = name.into();
        let mut minor_status = 0;
        let mut gss_name = ptr::null_mut();

        let major_status = unsafe {
            gssapi_krb5_sys::gss_import_name(&mut minor_status,
                                        name.get_handle(),
                                        name_type.get_handle(),
                                        &mut gss_name)
        };

        if major_status == gssapi_krb5_sys::GSS_S_COMPLETE {
            Ok(Name {
                name: gss_name,
                name_type: name_type,
            })
        } else {
            Err(Error::new(major_status, minor_status, name_type))
        }
    }

    /// Temporarily get wrapped value.
    pub unsafe fn get_handle(&self) -> gssapi_krb5_sys::gss_name_t {
        self.name
    }

    pub unsafe fn from_raw<T>(name: *mut T) -> Self {
        Name {
            name: name as gssapi_krb5_sys::gss_name_t,
            name_type: OID::krb_service(),
        }
    }

    /// Duplicate this name.
    pub fn duplicate(&self) -> Result<Self> {
        let mut minor_status = 0;
        let mut dst_name = ptr::null_mut();

        let major_status = unsafe {
            gssapi_krb5_sys::gss_duplicate_name(&mut minor_status, self.name, &mut dst_name)
        };

        if major_status == gssapi_krb5_sys::GSS_S_COMPLETE {
            Ok(Name {
                name: dst_name,
                name_type: self.name_type.clone(),
            })
        } else {
            Err(Error::new(major_status, minor_status, self.name_type.clone()))
        }
    }
}

impl Drop for Name {
    fn drop(&mut self) {
        let mut min_stat = 0;
        let maj_stat = unsafe {
            gssapi_krb5_sys::gss_release_name(&mut min_stat, &mut self.name)
        };

        if maj_stat != gssapi_krb5_sys::GSS_S_COMPLETE {
            panic!("failed to release name!");
        }
    }
}

impl Clone for Name {
    fn clone(&self) -> Self {
        self.duplicate().expect("duplication failed")
    }
}


impl std::convert::TryFrom<Name> for String {
    type Error = Error;
    fn try_from(other: Name) -> Result<String> {
        let mut buffer = Buffer::new();
        let mut minor_status = 0;
        let mut actual_mech_type = ptr::null_mut(); // ignore mech type

        let major_status = unsafe {
            gssapi_krb5_sys::gss_display_name(
                &mut minor_status,
                other.get_handle(),
                buffer.get_handle(),
                &mut actual_mech_type
            )
        };

        let actual_mech_type = unsafe { OID::new(actual_mech_type) };

        if major_status != gssapi_krb5_sys::GSS_S_COMPLETE {
            return Err(Error::new(major_status, minor_status, actual_mech_type))
        }

        Ok(String::from(buffer))
    }
}