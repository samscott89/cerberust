use gssapi_krb5_sys;
use std::ptr;
use super::buffer::BufferRef;
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
