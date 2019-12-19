use testor::acme_client::libs;
use testor::acme_client::libs::helper::{gen_key, b64, read_private_key, gen_csr};
use testor::acme_client::libs::error::{Result, ErrorKind};

pub fn test_acc(url: &str) -> Result<libs::v1::Account> {
    libs::v1::Directory::from_url(url )?
        .account_registration()
        .pkey_from_file("tests/data/user.key")?
        .register()
}