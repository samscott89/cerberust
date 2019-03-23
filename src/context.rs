use gssapi_krb5_sys;
use std::convert::TryInto;
use std::{mem, ptr};

use super::buffer::Buffer;
use super::credentials::Credentials;
use super::error::{Error, Result};
use super::name::Name;
use super::oid::OID;

#[derive(Debug)]
pub struct Context {
    context_handle: gssapi_krb5_sys::gss_ctx_id_t,
    mech_type: OID,
    time_rec: u32,
    flags: u32,
}

#[derive(Clone, Debug)]
pub struct ContextInfo {
    client: String,
    server: String,
}


impl Context {
    pub fn get_info(&self) -> Result<ContextInfo> {
        let mut minor_status = 0;
        let mut client = ptr::null_mut();
        let mut server = ptr::null_mut();

        let mut lifetime_rec = 0;
        let mut actual_mech_type = ptr::null_mut(); // ignore mech type
        let mut ret_flags = 0;
        let mut locally_initiated = 0;
        let mut open = 0;


        let major_status =  unsafe { gssapi_krb5_sys::gss_inquire_context(
            &mut minor_status,
            self.context_handle,
            &mut client,
            &mut server,
            &mut lifetime_rec,
            &mut actual_mech_type, 
            &mut ret_flags,
            &mut locally_initiated,
            &mut open
        )};

        let actual_mech_type = unsafe { OID::new_static(actual_mech_type) };

        if major_status != gssapi_krb5_sys::GSS_S_COMPLETE {
            return Err(Error::new(major_status, minor_status, actual_mech_type))
        }

        let client = unsafe { Name::from_raw(client).try_into()? };
        let server = unsafe { Name::from_raw(server).try_into()? };


        Ok(ContextInfo {
            client, server
        })
    }

}

impl Drop for Context {
    fn drop(&mut self) {
        let mut minor_status = 0;
        let major_status = unsafe {
            gssapi_krb5_sys::gss_delete_sec_context(
                &mut minor_status,
                &mut self.context_handle,
                ptr::null_mut())
        };

        if major_status != gssapi_krb5_sys::GSS_S_COMPLETE {
            panic!("failed to drop context {} {}", major_status, minor_status)
        }
    }
}


#[derive(Debug)]
pub struct InitiateContextBuilder {
    state: InitiateContextState,
}

impl InitiateContextBuilder {
    pub fn new<T: Into<Name>>(target_name: T) -> Self {
        InitiateContextBuilder {
            state: InitiateContextState::new(target_name),
        }
    }

    pub fn mech_type(mut self, mech_type: OID) -> Self {
        self.state.mech_type = mech_type;
        self
    }

    pub fn flags(mut self, flags: u32) -> Self {
        self.state.flags |= flags;
        self
    }

    pub fn build(self) -> InitiateContext {
        // Building the initial context involves driving the state forwards one step, with an empty input
        InitiateContext::Continue {
            state: self.state
        }
    }
}

#[derive(Debug)]
pub enum InitiateContext {
    Continue {
        state: InitiateContextState,
    },
    Done {
        context: Context,
    },
}

impl InitiateContext {
    pub fn step<T: Into<Buffer>>(&mut self, input: T) -> Result<Option<Buffer>> {
        // If already done, just return nothing
        let state = match *self {
            InitiateContext::Continue { ref mut state } => { state },
            _ => return Ok(None)
        };

        let mut minor_status = 0;
        let claimant_cred_handle = ptr::null_mut(); // no credentials
        let time_req = 0;
        let input_chan_bindings = ptr::null_mut(); // no channel bindings
        let mut actual_mech_type = ptr::null_mut(); // ignore mech type
        let mut output_token = Buffer::new();
        let mut ret_flags = 0;
        let mut time_rec = 0;

        let major_status = unsafe {
            gssapi_krb5_sys::gss_init_sec_context(
                &mut minor_status,
                claimant_cred_handle,
                &mut state.context_handle,
                state.target_name.get_handle(),
                state.mech_type.get_handle(),
                state.flags,
                time_req,
                input_chan_bindings,
                input.into().get_handle(),
                &mut actual_mech_type,
                output_token.get_handle(),
                &mut ret_flags,
                &mut time_rec,
            )
        };

        let actual_mech_type = unsafe { OID::new(actual_mech_type) };

        if state.context_handle.is_null() {
            panic!("cannot create context: {:?}", Error::new(major_status, minor_status, actual_mech_type));
        }


        if major_status == gssapi_krb5_sys::GSS_S_COMPLETE {
            let ctxt = InitiateContext::Done {
                context: Context {
                    context_handle: state.context_handle,
                    mech_type: actual_mech_type,
                    time_rec: time_rec,
                    flags: ret_flags,
                },
            };
            let _ = mem::replace(self, ctxt);

            Ok(None)
        } else if major_status == gssapi_krb5_sys::GSS_S_CONTINUE_NEEDED {
            Ok(Some(output_token))
        } else {
            Err(Error::new(major_status, minor_status, actual_mech_type))
        }
    }
}

#[derive(Debug)]
pub struct InitiateContextState {
    target_name: Name,
    mech_type: OID,
    flags: u32,
    context_handle: gssapi_krb5_sys::gss_ctx_id_t,
}

impl InitiateContextState {
    fn new<T: Into<Name>>(target_name: T) -> Self {
        let target_name = target_name.into();

        InitiateContextState {
            target_name: target_name,
            mech_type: OID::empty(),
            flags: 0,
            context_handle: ptr::null_mut(),
        }
    }
}

#[derive(Debug)]
pub struct AcceptContextBuilder {
    state: AcceptContextState,
}

impl AcceptContextBuilder {
    pub fn new(credentials: Credentials) -> Self {
        AcceptContextBuilder {
            state: AcceptContextState::new(credentials),
        }
    }

    pub fn step(self, input_token: Buffer) -> Result<AcceptContext> {
        self.state.step(input_token)
    }
}

#[derive(Debug)]
pub enum AcceptContext {
    Continue {
        acceptor: AcceptContextState,
        token: Buffer,
    },
    Done {
        context: Context,
        token: Buffer,
    },
}

#[derive(Debug)]
pub struct AcceptContextState {
    acceptor_credentials: Credentials,
    context_handle: gssapi_krb5_sys::gss_ctx_id_t,
}

impl AcceptContextState {
    fn new(credentials: Credentials) -> Self {
        AcceptContextState {
            acceptor_credentials: credentials,
            context_handle: ptr::null_mut(),
        }
    }

    pub fn step(mut self, mut input_token: Buffer) -> Result<AcceptContext> {
        let mut minor_status = 0;
        let input_chan_bindings = ptr::null_mut(); // no channel bindings
        let mut src_name = ptr::null_mut();
        let mut mech_type = ptr::null_mut(); // ignore mech type
        let mut output_token = Buffer::new();
        let mut ret_flags = 0;
        let mut time_rec = 0;
        let mut delegated_cred_handle = ptr::null_mut();

        let major_status = unsafe {
            gssapi_krb5_sys::gss_accept_sec_context(
                &mut minor_status,
                &mut self.context_handle,
                self.acceptor_credentials.get_handle(),
                input_token.get_handle(),
                input_chan_bindings,
                &mut src_name,
                &mut mech_type,
                output_token.get_handle(),
                &mut ret_flags,
                &mut time_rec,
                &mut delegated_cred_handle,
            )
        };

        if self.context_handle.is_null() {
            panic!("cannot create context");
        }

        let mech_type = unsafe { OID::new(mech_type) };

        if major_status == gssapi_krb5_sys::GSS_S_COMPLETE {
            Ok(AcceptContext::Done {
                context: Context {
                    context_handle: self.context_handle,
                    mech_type: mech_type,
                    time_rec: time_rec,
                    flags: ret_flags,
                },
                token: output_token,
            })
        } else if major_status == gssapi_krb5_sys::GSS_S_CONTINUE_NEEDED {
            Ok(AcceptContext::Continue {
                acceptor: self,
                token: output_token,
            })
        } else {
            Err(Error::new(major_status, minor_status, mech_type))
        }
    }
}
