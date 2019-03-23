use gssapi_krb5_sys;
use std::ptr;
use crate::error::Error;

#[derive(Clone, Debug)]
pub struct OID {
    oid: gssapi_krb5_sys::gss_OID,
    owned: bool,
}

const KRB5_MECH_OID_BYTES: &[u8] = b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02";
const KRB5_MECH_OID: gssapi_krb5_sys::gss_OID_desc_struct = 
    gssapi_krb5_sys::gss_OID_desc_struct  { length: 9, elements: KRB5_MECH_OID_BYTES.as_ptr() as *mut std::ffi::c_void };

impl OID {
    pub unsafe fn new<T>(oid: *mut T) -> Self {
        OID {
            oid: oid as gssapi_krb5_sys::gss_OID,
            owned: true,
        }
    }

    pub unsafe fn new_static<T>(oid: *mut T) -> Self {
        OID {
            oid: oid as gssapi_krb5_sys::gss_OID,
            owned: false,
        }
    }

    pub fn empty() -> Self {
        unsafe { OID::new::<gssapi_krb5_sys::gss_OID>(ptr::null_mut()) }
    }

    pub fn nt_hostbased_service() -> Self {
        unsafe {
            Self::new_static(gssapi_krb5_sys::GSS_C_NT_HOSTBASED_SERVICE)
        }
    }
    
    pub fn nt_user_name() -> Self {
        unsafe {
            Self::new_static(gssapi_krb5_sys::GSS_C_NT_USER_NAME)
        }
    }

    pub fn krb_service() -> Self {
        unsafe {
            Self::new_static(gssapi_krb5_sys::GSS_KRB5_NT_PRINCIPAL_NAME as *mut gssapi_krb5_sys::gss_OID)
        }
    }

    pub unsafe fn get_handle(&self) -> gssapi_krb5_sys::gss_OID {
        self.oid
    }
}

impl Drop for OID {
    fn drop(&mut self) {
        if self.owned {
            let mut minor_status = 0;
            let major_status = unsafe {
                gssapi_krb5_sys::gss_release_oid(
                    &mut minor_status,
                    &mut self.oid)
            };

            if major_status != gssapi_krb5_sys::GSS_S_COMPLETE {
                let err = Error::new(major_status, minor_status, OID::empty());
                panic!("{}", err);
            }
        }
    }
}
