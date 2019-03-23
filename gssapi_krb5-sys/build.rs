extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    // Tell cargo to tell rustc to link the system krb5
    // shared library.
    println!("cargo:rustc-link-lib=krb5");
    println!("cargo:rustc-link-lib=gssapi_krb5");

    let gss_types = "^(OM_.+|gss_.+)";
    let gss_vars = "^GSS_.+";
    let gss_funcs = "^gss_.*";
    let krb_types = "^krb5_.+";
    let krb_vars = "^KRB5_.+";
    let krb_funcs = "^krb5_.*";
    

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("wrapper.h");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    // #[cfg(target_os="macos")]
    // let gssapi = gssapi.header("includes/osx.h");

    let bindings = bindings
      .whitelist_type(gss_types)
      .whitelist_var(gss_vars)
      .whitelist_function(gss_funcs)
      .whitelist_type(krb_types)
      .whitelist_var(krb_vars)
      .whitelist_function(krb_funcs)
      .generate()
      .expect("Unable to generate <krb5.h> or <gssapi.h> bindings");
    bindings.write_to_file(out_path.join("bindings.rs")).expect("Couldn't write <krb5.h> or <gssapi.h> bindings!");

}