#include <krb5.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>

#include "include/kerberosgss.h"


int gss_error(int x) {
	return GSS_ERROR(x);
}

/**
 * <div rustbindgen replaces="gss_OID_set_desc_struct"></div>
 */
typedef struct gss_oid_set_desc_struct { // gss/lib/headers/gss/api.h
  size_t count;
  gss_OID *elements;
};

/**
 * <div rustbindgen replaces="gss_name_struct"></div>
 */
typedef struct gss_name_struct { // gss/lib/internal.h
  size_t length;
  char *value;
  gss_OID type;
} gss_name_desc;

/**
 * <div rustbindgen replaces="gss_cred_id_struct"></div>
 */
typedef struct gss_cred_id_struct { // gss/lib/internal.h
  gss_OID mech;
#ifdef USE_KERBEROS5
  struct _gss_krb5_cred_struct *krb5;
#endif
} gss_cred_id_desc;

/**
 * <div rustbindgen replaces="gss_ctx_id_struct"></div>
 */
typedef struct gss_ctx_id_struct { // gss/lib/internal.h
  gss_OID mech;
#ifdef USE_KERBEROS5
  struct _gss_krb5_ctx_struct *krb5;
#endif
} gss_ctx_id_desc;
