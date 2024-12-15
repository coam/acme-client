use acme_client::libs;
use acme_client::libs::error::{ErrorKind, Result};
use acme_client::libs::helper::{b64, gen_csr, gen_key, read_private_key};

pub fn test_acc(url: &str) -> Result<libs::v1::Account> {
    libs::v1::Directory::from_url(url)?
        .account_registration()
        .pkey_from_file("tests/data/user.key")?
        .register()
}
