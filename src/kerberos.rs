use gssapi_krb5_sys as ffi;

use std::ops::Deref;
use std::ptr;

use crate::{buffer, context, credentials, name, oid};
use crate::error::{Error, Result};


pub struct GssClientConfig {
    pub mech_oid: oid::OID,
    pub gss_flags: u32,
    client_creds: Option<credentials::Credentials>,
}

impl GssClientConfig {
    pub fn new() -> Self {
        GssClientConfig {
            mech_oid: oid::OID::krb_service(),
            gss_flags: ffi::GSS_C_MUTUAL_FLAG | ffi::GSS_C_SEQUENCE_FLAG,
            client_creds: None,
        }
    }

    pub fn with_principal(principal: &str) -> Result<Self> {
        let mut res = Self::new();
        let creds = name::Name::new(principal, oid::OID::krb_service())
            .map(|name| credentials::Credentials::accept(name))
            .and_then(|builder| builder.build())?;
    
        res.client_creds = Some(creds);
        Ok(res)
    }

    pub fn with_delegate_state(credentials: credentials::Credentials) -> Self {
        let mut res = Self::new();
        res.client_creds = Some(credentials);
        res
    }

    /// This gives the mechanism type.
    /// Using null seems to work frequently, so maybe ignore.
    pub fn mech_oid(&mut self, oid: oid::OID) -> &mut Self {
        self.mech_oid = oid;
        self
    }

    pub fn flags(&mut self, flags: u32) -> &mut Self {
        self.gss_flags = flags;
        self
    }

    pub fn start_auth(&self, server_name: &str) -> Result<context::InitiateContext> {
        let name = name::Name::new(server_name, self.mech_oid.clone())?;
        Ok(context::InitiateContextBuilder::new(name)
            // .mech_type(self.mech_oid.clone())
            .flags(self.gss_flags)
            .build())
    }
}

pub struct GssServerState {
    context: context::Context,
    server_name: name::Name,
    client_name: name::Name,
    server_creds: credentials::Credentials,
    client_creds: credentials::Credentials,
    username: Option<String>,
    targetname: Option<String>,
    response: Option<String>,
    ccname: Option<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_init() {
        let cfg = GssClientConfig::new();
        let mut ctxt = cfg.start_auth("test_server").unwrap();
        let buf = ctxt.step(buffer::Buffer::new()).unwrap();
        println!("{:#?}", buf);
    }
}