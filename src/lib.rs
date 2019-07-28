pub extern crate openssl;
#[macro_use]
extern crate log;
//extern crate env_logger;
//extern crate pretty_env_logger;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate hyper;
extern crate reqwest;
//extern crate serde;
//extern crate serde_json;
extern crate base64;

#[macro_use]
extern crate serde_derive;

extern crate serde;
extern crate serde_json;

pub mod libs;

use libs::v1;

use libs::helper::{gen_key, b64, read_pkey, gen_csr};
use libs::error::{Result, ErrorKind};

///// Error and result types.
//pub mod error {
//
//}


///// Various helper functions.
//pub mod helper {
//
//}
