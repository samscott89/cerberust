use crate::*;

use std::{ptr, mem};

static krb5_mech_oid_bytes: &'static [u8] = b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02";
const krb5_mech_oid: gss_OID_desc = gss_OID_desc_struct { length: 9, elements: &krb5_mech_oid_byte };
static spnego_mech_oid_bytes: &'static [u8] = b"\x2b\x06\x01\x05\x05\x02";
const spnego_mech_oid: gss_OID_desc = gss_OID_desc_struct { length: 6, elements: &spnego_mech_oid_bytes };

struct KrbError;
struct BasicAuthError;
struct PwdChangeError;
struct GssError(u32, u32);

struct GssClient {
    state: gss_client_state,
    delegate_state: Option<gss_server_state>,
}

impl Drop for GssClient {
    fn drop(self) {
        if !state.is_null() {
            unsafe {
                authenticate_gss_client_clean(&mut state);
            }
        }
    }
}

fn import_name(name: &str) -> Result<gss_name_t, GssError> {
    let mut name_token = gss_buffer_desc_struct {
        length: len(name),
        value: name.as_ptr(),
    };
    let mut min_stat = 0;
    let mut output: gss_name_struct = mem::unintialized();
    let res = unsafe {
        gss_import_name(
            &mut internal_res,
            &name_token,
            &krb5_mech_oid),
            &mut output,
        )
    };

    if gss_calling_error(res) {
        Err(GssError(res, min_stat))
    } else {
        Ok(Box::into_raw(Box::new(output)))
    }
}

impl GssClient {
    fn new(service: &str, delegate_state: Option<gss_server_state>, principal: Option<&str>) -> Self {
        let server_name = import_name(service).unwrap();

        // Use the delegate credentials if they exist
        let client_creds = if let Some(state) = delegate_state {
            state.client_creds
        }
        // If available use the principal to extract its associated credentials
        else if let Some(principal) = principal {
            let mut client_creds: gss_cred_id_t = mem::unintialized();
            let principal = import_name(principal).unwrap();

            let mut min_stat = 0;
            let res = unsafe {
                gss_acquire_cred(
                    &0,
                    &principal,
                    GSS_C_INDEFINITE,
                    GSS_C_NO_OID_SET,
                    GSS_C_INITIATE,
                    &client_creds, 
                    0,
                    0
                )
            };

            if gss_calling_error(res) {
                // return Err(GssError(res, min_stat));
                panic!("Failed to acquire credentials");
            } else {
                Box::into_raw(Box::new(output))
            }
        } else {
            ptr::null()
        }

        }

        else if (principal && *principal) {
            maj_stat = gss_acquire_cred(
                &min_stat, name, GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
                GSS_C_INITIATE, &state->client_creds, NULL, NULL
            );
            if (GSS_ERROR(maj_stat)) {
                set_gss_error(maj_stat, min_stat);
                ret = AUTH_GSS_ERROR;
                goto end;
            }

            maj_stat = gss_release_name(&min_stat, &name);
            if (GSS_ERROR(maj_stat)) {
                set_gss_error(maj_stat, min_stat);
                ret = AUTH_GSS_ERROR;
                goto end;
            }
        }

        let state = gss_client_state {
            context: ptr::null(),
            server_name,
            mech_oid: &krb5_mech_oid,
            gss_flags:  GSS_C_MUTUAL_FLAG | GSS_C_SEQUENCE_FLAG,
            client_creds,
            username: ptr::null(),
            response: ptr::null(),
            responseConf: ptr::null(),
        }

        Service {
            state, None
        }
    }
}

int authenticate_gss_client_init(
    const char* service, const char* principal, long int gss_flags,
    gss_server_state* delegatestate, gss_OID mech_oid, gss_client_state* state
)
{
    

end:
    return ret;
}


static PyObject* authGSSClientInit(PyObject* self, PyObject* args, PyObject* keywds)
{
    gss_OID mech_oid = GSS_C_NO_OID;
    long int gss_flags = GSS_C_MUTUAL_FLAG | GSS_C_SEQUENCE_FLAG;

    result = authenticate_gss_client_init(
        service, principal, gss_flags, delegatestate, mech_oid, state
    );

    if (result == AUTH_GSS_ERROR) {
        return NULL;
    }

    return Py_BuildValue("(iO)", result, pystate);
}

static PyObject *authGSSClientClean(PyObject *self, PyObject *args)
{
    return Py_BuildValue("i", AUTH_GSS_COMPLETE);
}

#if PY_VERSION_HEX >= 0x03020000
void destruct_channel_bindings(PyObject* o) {
    struct gss_channel_bindings_struct *channel_bindings = PyCapsule_GetPointer(o, NULL);
#else
void destruct_channel_bindings(void* o) {
    struct gss_channel_bindings_struct *channel_bindings = (struct gss_channel_bindings_struct *)o;
#endif

    if (channel_bindings != NULL) {
        if (channel_bindings->initiator_address.value != NULL) {
            PyMem_Free(channel_bindings->initiator_address.value);
        }

        if (channel_bindings->acceptor_address.value != NULL) {
            PyMem_Free(channel_bindings->acceptor_address.value);
        }

        if (channel_bindings->application_data.value != NULL) {
            PyMem_Free(channel_bindings->application_data.value);
        }

        free(channel_bindings);
    }
}

static PyObject *channelBindings(PyObject *self, PyObject *args, PyObject* keywds)
{
    int initiator_addrtype = GSS_C_AF_UNSPEC;
    int acceptor_addrtype = GSS_C_AF_UNSPEC;

    const char *encoding = NULL;
    char *initiator_address = NULL;
    char *acceptor_address = NULL;
    char *application_data = NULL;
    int initiator_length = 0;
    int acceptor_length = 0;
    int application_length = 0;

    PyObject *pychan_bindings = NULL;
    struct gss_channel_bindings_struct *input_chan_bindings;
    static char *kwlist[] = {"initiator_addrtype", "initiator_address", "acceptor_addrtype",
        "acceptor_address", "application_data", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "|iet#iet#et#", kwlist,
            &initiator_addrtype, &encoding, &initiator_address, &initiator_length,
            &acceptor_addrtype, &encoding, &acceptor_address, &acceptor_length,
            &encoding, &application_data, &application_length)) {
        return NULL;
    }

    input_chan_bindings = (struct gss_channel_bindings_struct *) malloc(sizeof(struct gss_channel_bindings_struct));
    pychan_bindings = PyCObject_FromVoidPtr(input_chan_bindings, &destruct_channel_bindings);

    input_chan_bindings->initiator_addrtype = initiator_addrtype;
    input_chan_bindings->initiator_address.length = initiator_length;
    input_chan_bindings->initiator_address.value = initiator_address;

    input_chan_bindings->acceptor_addrtype = acceptor_addrtype;
    input_chan_bindings->acceptor_address.length = acceptor_length;
    input_chan_bindings->acceptor_address.value = acceptor_address;

    input_chan_bindings->application_data.length = application_length;
    input_chan_bindings->application_data.value = application_data;

    return Py_BuildValue("N", pychan_bindings);
}

static PyObject *authGSSClientStep(PyObject *self, PyObject *args, PyObject* keywds)
{
    gss_client_state *state = NULL;
    PyObject *pystate = NULL;
    char *challenge = NULL;
    PyObject *pychan_bindings = NULL;
    struct gss_channel_bindings_struct *channel_bindings;
    static char *kwlist[] = {"state", "challenge", "channel_bindings", NULL};
    int result = 0;

    if (! PyArg_ParseTupleAndKeywords(args, keywds, "Os|O", kwlist, &pystate, &challenge, &pychan_bindings)) {
        return NULL;
    }

    if (! PyCObject_Check(pystate)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }

    state = (gss_client_state *)PyCObject_AsVoidPtr(pystate);

    if (state == NULL) {
        return NULL;
    }

    if (pychan_bindings == NULL) {
        channel_bindings = GSS_C_NO_CHANNEL_BINDINGS;
    } else {
        if (!PyCObject_Check(pychan_bindings)) {
            PyErr_SetString(PyExc_TypeError, "Expected a gss_channel_bindings_struct object");
            return NULL;
        }
        channel_bindings = (struct gss_channel_bindings_struct *)PyCObject_AsVoidPtr(pychan_bindings);
    }

    result = authenticate_gss_client_step(state, challenge, channel_bindings);

    if (result == AUTH_GSS_ERROR) {
        return NULL;
    }

    return Py_BuildValue("i", result);
}

static PyObject *authGSSClientResponseConf(PyObject *self, PyObject *args)
{
    gss_client_state *state = NULL;
    PyObject *pystate = NULL;

    if (! PyArg_ParseTuple(args, "O", &pystate)) {
        return NULL;
    }

    if (! PyCObject_Check(pystate)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }

    state = (gss_client_state *)PyCObject_AsVoidPtr(pystate);

    if (state == NULL) {
        return NULL;
    }

    return Py_BuildValue("i", state->responseConf);
}

static PyObject *authGSSServerHasDelegated(PyObject *self, PyObject *args)
{
    gss_server_state *state = NULL;
    PyObject *pystate = NULL;

    if (! PyArg_ParseTuple(args, "O", &pystate)) {
        return NULL;
    }

    if (! PyCObject_Check(pystate)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }

    state = (gss_server_state *)PyCObject_AsVoidPtr(pystate);

    if (state == NULL) {
        return NULL;
    }

    return PyBool_FromLong(authenticate_gss_server_has_delegated(state));
}

static PyObject *authGSSClientResponse(PyObject *self, PyObject *args)
{
    gss_client_state *state = NULL;
    PyObject *pystate = NULL;

    if (! PyArg_ParseTuple(args, "O", &pystate)) {
        return NULL;
    }

    if (! PyCObject_Check(pystate)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }

    state = (gss_client_state *)PyCObject_AsVoidPtr(pystate);

    if (state == NULL) {
        return NULL;
    }

    return Py_BuildValue("s", state->response);
}

static PyObject *authGSSClientUserName(PyObject *self, PyObject *args)
{
    gss_client_state *state = NULL;
    PyObject *pystate = NULL;

    if (! PyArg_ParseTuple(args, "O", &pystate)) {
        return NULL;
    }

    if (! PyCObject_Check(pystate)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }

    state = (gss_client_state *)PyCObject_AsVoidPtr(pystate);

    if (state == NULL) {
        return NULL;
    }

    return Py_BuildValue("s", state->username);
}

static PyObject *authGSSClientUnwrap(PyObject *self, PyObject *args)
{
	gss_client_state *state = NULL;
	PyObject *pystate = NULL;
	char *challenge = NULL;
	int result = 0;

	if (! PyArg_ParseTuple(args, "Os", &pystate, &challenge)) {
		return NULL;
    }

	if (! PyCObject_Check(pystate)) {
		PyErr_SetString(PyExc_TypeError, "Expected a context object");
		return NULL;
	}

	state = (gss_client_state *)PyCObject_AsVoidPtr(pystate);

	if (state == NULL) {
		return NULL;
    }

	result = authenticate_gss_client_unwrap(state, challenge);

	if (result == AUTH_GSS_ERROR) {
		return NULL;
    }

	return Py_BuildValue("i", result);
}

static PyObject *authGSSClientWrap(PyObject *self, PyObject *args)
{
	gss_client_state *state = NULL;
	PyObject *pystate = NULL;
	char *challenge = NULL;
	char *user = NULL;
	int protect = 0;
	int result = 0;

	if (! PyArg_ParseTuple(
        args, "Os|zi", &pystate, &challenge, &user, &protect
    )) {
		return NULL;
    }

	if (! PyCObject_Check(pystate)) {
		PyErr_SetString(PyExc_TypeError, "Expected a context object");
		return NULL;
	}

	state = (gss_client_state *)PyCObject_AsVoidPtr(pystate);

	if (state == NULL) {
		return NULL;
    }

	result = authenticate_gss_client_wrap(state, challenge, user, protect);

	if (result == AUTH_GSS_ERROR) {
		return NULL;
    }

	return Py_BuildValue("i", result);
}

static PyObject *authGSSClientInquireCred(PyObject *self, PyObject *args)
{
    gss_client_state *state = NULL;
    PyObject *pystate = NULL;
    int result = 0;
    if (!PyArg_ParseTuple(args, "O", &pystate)) {
        return NULL;
    }

    if (!PyCObject_Check(pystate)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }

    state = (gss_client_state *)PyCObject_AsVoidPtr(pystate);
    if (state == NULL) {
        return NULL;
    }

    result = authenticate_gss_client_inquire_cred(state);
    if (result == AUTH_GSS_ERROR) {
        return NULL;
    }

    return Py_BuildValue("i", result);
}

static void
#if PY_VERSION_HEX >= 0x03020000
destroy_gss_server(PyObject *obj) {
    gss_server_state *state = PyCapsule_GetPointer(obj, NULL);
#else
destroy_gss_server(void *obj) {
    gss_server_state *state = (gss_server_state *)obj;
#endif
    if (state) {
        authenticate_gss_server_clean(state);
        free(state);
    }
}

static PyObject *authGSSServerInit(PyObject *self, PyObject *args)
{
    const char *service = NULL;
    gss_server_state *state = NULL;
    PyObject *pystate = NULL;
    int result = 0;

    if (! PyArg_ParseTuple(args, "s", &service)) {
        return NULL;
    }

    state = (gss_server_state *) malloc(sizeof(gss_server_state));
    if (state == NULL)
    {
        PyErr_NoMemory();
        return NULL;
    }
    pystate = PyCObject_FromVoidPtr(state, &destroy_gss_server);

    result = authenticate_gss_server_init(service, state);

    if (result == AUTH_GSS_ERROR) {
        return NULL;
    }

    return Py_BuildValue("(iO)", result, pystate);
}

static PyObject *authGSSServerClean(PyObject *self, PyObject *args)
{
    return Py_BuildValue("i", AUTH_GSS_COMPLETE);
}

static PyObject *authGSSServerStep(PyObject *self, PyObject *args)
{
    gss_server_state *state = NULL;
    PyObject *pystate = NULL;
    char *challenge = NULL;
    int result = 0;

    if (! PyArg_ParseTuple(args, "Os", &pystate, &challenge)) {
        return NULL;
    }

    if (! PyCObject_Check(pystate)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }

    state = (gss_server_state *)PyCObject_AsVoidPtr(pystate);

    if (state == NULL) {
        return NULL;
    }

    result = authenticate_gss_server_step(state, challenge);

    if (result == AUTH_GSS_ERROR) {
        return NULL;
    }

    return Py_BuildValue("i", result);
}

static PyObject *authGSSServerStoreDelegate(PyObject *self, PyObject *args)
{
    gss_server_state *state = NULL;
    PyObject *pystate = NULL;
    int result = 0;

    if (! PyArg_ParseTuple(args, "O", &pystate)) {
        return NULL;
    }

    if (! PyCObject_Check(pystate)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }

    state = (gss_server_state *)PyCObject_AsVoidPtr(pystate);

    if (state == NULL) {
        return NULL;
    }

    result = authenticate_gss_server_store_delegate(state);

    if (result == AUTH_GSS_ERROR) {
        return NULL;
    }
    
    return Py_BuildValue("i", result);
}

static PyObject *authGSSServerResponse(PyObject *self, PyObject *args)
{
    gss_server_state *state = NULL;
    PyObject *pystate = NULL;

    if (! PyArg_ParseTuple(args, "O", &pystate)) {
        return NULL;
    }

    if (! PyCObject_Check(pystate)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }

    state = (gss_server_state *)PyCObject_AsVoidPtr(pystate);

    if (state == NULL) {
        return NULL;
    }

    return Py_BuildValue("s", state->response);
}

static PyObject *authGSSServerUserName(PyObject *self, PyObject *args)
{
    gss_server_state *state = NULL;
    PyObject *pystate = NULL;
    
    if (! PyArg_ParseTuple(args, "O", &pystate)) {
        return NULL;
    }
    
    if (! PyCObject_Check(pystate)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }
    
    state = (gss_server_state *)PyCObject_AsVoidPtr(pystate);

    if (state == NULL) {
        return NULL;
    }
    
    return Py_BuildValue("s", state->username);
}

static PyObject *authGSSServerCacheName(PyObject *self, PyObject *args)
{
    gss_server_state *state = NULL;
    PyObject *pystate = NULL;
    
    if (! PyArg_ParseTuple(args, "O", &pystate)) {
        return NULL;
    }
    
    if (! PyCObject_Check(pystate)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }
    
    state = (gss_server_state *)PyCObject_AsVoidPtr(pystate);

    if (state == NULL) {
        return NULL;
    }

    return Py_BuildValue("s", state->ccname);
}

static PyObject *authGSSServerTargetName(PyObject *self, PyObject *args)
{
    gss_server_state *state = NULL;
    PyObject *pystate = NULL;
    
    if (! PyArg_ParseTuple(args, "O", &pystate)) {
        return NULL;
    }
    
    if (! PyCObject_Check(pystate)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }
    
    state = (gss_server_state *)PyCObject_AsVoidPtr(pystate);

    if (state == NULL) {
        return NULL;
    }
    
    return Py_BuildValue("s", state->targetname);
}

static PyMethodDef KerberosMethods[] = {
    {
        "checkPassword",
        checkPassword, METH_VARARGS,
        "Check the supplied user/password against Kerberos KDC."
    },
    {
        "changePassword",
        changePassword, METH_VARARGS,
        "Change the user password."
    },
    {
        "getServerPrincipalDetails",
        getServerPrincipalDetails, METH_VARARGS,
        "Return the service principal for a given service and hostname."
    },
    {
        "authGSSClientInit",
        (PyCFunction)authGSSClientInit, METH_VARARGS | METH_KEYWORDS,
        "Initialize client-side GSSAPI operations."
    },
    {
        "channelBindings",
        (PyCFunction)channelBindings, METH_VARARGS | METH_KEYWORDS,
        "Build the Channel Bindings Structure for authGSSClientStep."
    },
    {
        "authGSSClientClean",
        authGSSClientClean, METH_VARARGS,
        "Terminate client-side GSSAPI operations."
    },
    {
        "authGSSClientStep",
        (PyCFunction)authGSSClientStep, METH_VARARGS | METH_KEYWORDS,
        "Do a client-side GSSAPI step."
    },
    {
        "authGSSClientResponse",
        authGSSClientResponse, METH_VARARGS,
        "Get the response from the last client-side GSSAPI step."
    },
    {
        "authGSSClientInquireCred",  authGSSClientInquireCred, METH_VARARGS,
        "Get the current user name, if any, without a client-side GSSAPI step"
    },
    {
        "authGSSClientResponseConf",
        authGSSClientResponseConf, METH_VARARGS,
        "return 1 if confidentiality was set in the last unwrapped buffer, 0 otherwise."
    },
    {
        "authGSSClientUserName",
        authGSSClientUserName, METH_VARARGS,
        "Get the user name from the last client-side GSSAPI step."
    },
    {
        "authGSSServerInit",
        authGSSServerInit, METH_VARARGS,
        "Initialize server-side GSSAPI operations."
    },
    {
        "authGSSClientWrap",
        authGSSClientWrap, METH_VARARGS,
        "Do a GSSAPI wrap."
    },
    {
        "authGSSClientUnwrap",
        authGSSClientUnwrap, METH_VARARGS,
        "Do a GSSAPI unwrap."
    },
    {
        "authGSSClientInquireCred", authGSSClientInquireCred, METH_VARARGS,
        "Get the current user name, if any."
    },
    {
        "authGSSServerClean",
        authGSSServerClean, METH_VARARGS,
        "Terminate server-side GSSAPI operations."
    },
    {
        "authGSSServerStep",
        authGSSServerStep, METH_VARARGS,
        "Do a server-side GSSAPI step."
    },
    {
        "authGSSServerHasDelegated",
        authGSSServerHasDelegated, METH_VARARGS,
        "Check whether the client delegated credentials to us."
    },
    {
        "authGSSServerStoreDelegate",
        authGSSServerStoreDelegate, METH_VARARGS,
        "Store the delegated Credentials."
    },
    {
        "authGSSServerResponse",
        authGSSServerResponse, METH_VARARGS,
        "Get the response from the last server-side GSSAPI step."
    },
    {
        "authGSSServerUserName",
        authGSSServerUserName, METH_VARARGS,
        "Get the user name from the last server-side GSSAPI step."
    },
    {
        "authGSSServerCacheName",
        authGSSServerCacheName, METH_VARARGS,
        "Get the location of the cache where delegated credentials are stored."
    },
    {
        "authGSSServerTargetName",
        authGSSServerTargetName, METH_VARARGS,
        "Get the target name from the last server-side GSSAPI step."
    },
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

MOD_INIT(kerberos)
{
    PyObject *m,*d;

    MOD_DEF(m, "kerberos", NULL, KerberosMethods);

    if (m == NULL) {
        return MOD_ERROR_VAL;
    }

    d = PyModule_GetDict(m);

    /* create the base exception class */
    if (! (KrbException_class = PyErr_NewException(
        "kerberos.KrbError", NULL, NULL
    ))) {
        goto error;
    }

    PyDict_SetItemString(d, "KrbError", KrbException_class);
    Py_INCREF(KrbException_class);

    /* ...and the derived exceptions */
    if (! (BasicAuthException_class = PyErr_NewException(
        "kerberos.BasicAuthError", KrbException_class, NULL
    ))) {
        goto error;
    }

    Py_INCREF(BasicAuthException_class);
    PyDict_SetItemString(d, "BasicAuthError", BasicAuthException_class);

    if (! (PwdChangeException_class = PyErr_NewException(
        "kerberos.PwdChangeError", KrbException_class, NULL
    ))) {
        goto error;
    }

    Py_INCREF(PwdChangeException_class);
    PyDict_SetItemString(d, "PwdChangeError", PwdChangeException_class);

    if (! (GssException_class = PyErr_NewException(
        "kerberos.GSSError", KrbException_class, NULL
    ))) {
        goto error;
    }

    Py_INCREF(GssException_class);
    PyDict_SetItemString(
        d, "GSSError", GssException_class
    );

    PyDict_SetItemString(
        d, "AUTH_GSS_COMPLETE", PyInt_FromLong(AUTH_GSS_COMPLETE)
    );
    PyDict_SetItemString(
        d, "AUTH_GSS_CONTINUE", PyInt_FromLong(AUTH_GSS_CONTINUE)
    );

    PyDict_SetItemString(
        d, "GSS_C_DELEG_FLAG", PyInt_FromLong(GSS_C_DELEG_FLAG)
    );
    PyDict_SetItemString(
        d, "GSS_C_MUTUAL_FLAG", PyInt_FromLong(GSS_C_MUTUAL_FLAG)
    );
    PyDict_SetItemString(
        d, "GSS_C_REPLAY_FLAG", PyInt_FromLong(GSS_C_REPLAY_FLAG)
    );
    PyDict_SetItemString(
        d, "GSS_C_SEQUENCE_FLAG", PyInt_FromLong(GSS_C_SEQUENCE_FLAG)
    );
    PyDict_SetItemString(
        d, "GSS_C_CONF_FLAG", PyInt_FromLong(GSS_C_CONF_FLAG)
    );
    PyDict_SetItemString(
        d, "GSS_C_INTEG_FLAG", PyInt_FromLong(GSS_C_INTEG_FLAG)
    );
    PyDict_SetItemString(
        d, "GSS_C_ANON_FLAG", PyInt_FromLong(GSS_C_ANON_FLAG)
    );
    PyDict_SetItemString(
        d, "GSS_C_PROT_READY_FLAG", PyInt_FromLong(GSS_C_PROT_READY_FLAG)
    );
    PyDict_SetItemString(
        d, "GSS_C_TRANS_FLAG", PyInt_FromLong(GSS_C_TRANS_FLAG)
    );
    PyDict_SetItemString(
        d, "GSS_MECH_OID_KRB5", PyCObject_FromVoidPtr(&krb5_mech_oid, NULL)
    );
    PyDict_SetItemString(
        d, "GSS_MECH_OID_SPNEGO", PyCObject_FromVoidPtr(&spnego_mech_oid, NULL)
    );

error:
    if (PyErr_Occurred()) {
         PyErr_SetString(PyExc_ImportError, "kerberos: init failed");
        return MOD_ERROR_VAL;
    }

    return MOD_SUCCESS_VAL(m);
}
