#![feature(plugin, decl_macro)]

extern crate acme_client;
extern crate env_logger;

#[macro_use]
extern crate log;
extern crate pretty_env_logger;

use acme_client::libs;

use libs::helper::{gen_key, b64, read_private_key, gen_csr};
use libs::error::{Result, ErrorKind};

// 测试模块...
pub mod testor;

// 调试输出
//cargo test -- --nocapture

// 调试地址
const LETS_ENCRYPT_V1_STAGING_DIRECTORY_URL: &'static str = "https://acme-staging.api.letsencrypt.org/directory";
const LETS_ENCRYPT_V2_STAGING_DIRECTORY_URL: &'static str = "https://acme-staging-v02.api.letsencrypt.org/directory";

#[test]
fn test_gen_key() {
    assert!(gen_key().is_ok())
}

#[test]
fn test_b64() {
    assert_eq!(b64(&"foobar".to_string().into_bytes()), "Zm9vYmFy");
}

#[test]
fn test_read_private_key() {
    assert!(read_private_key("tests/data/user.key").is_ok());
}

#[test]
fn test_gen_csr() {
    let pkey = gen_key().unwrap();
    assert!(gen_csr(&pkey, &["example.com"]).is_ok());
    assert!(gen_csr(&pkey, &["example.com", "sub.example.com"]).is_ok());
}

#[test]
fn test_v2_directory() {
    //let directory = libs::v2::AcmeAuthDirectory::lets_encrypt().unwrap();
    //println!("[###]AcmeAuthDirectory.lets_encrypt():[directory.url:{:?}][directory.directory:{:?}]", directory.url,directory.directory);

    assert!(libs::v2::AcmeAuthDirectory::lets_encrypt().is_ok());

    let dir = libs::v2::AcmeAuthDirectory::from_url(LETS_ENCRYPT_V2_STAGING_DIRECTORY_URL).unwrap();
    println!("[###]AcmeAuthDirectory.newAccount:{:?}", dir.get_acme_resource_url("newAccount").unwrap());

    assert!(dir.get_acme_resource_url("newAccount").is_some());
    assert!(dir.get_acme_resource_url("newNonce").is_some());
    assert!(dir.get_acme_resource_url("newOrder").is_some());
    assert!(dir.get_acme_resource_url("revokeCert").is_some());

    //assert!(!dir.get_nonce().unwrap().is_empty());

    let pkey = gen_key().unwrap();
    assert!(dir.jwk(&pkey).is_ok());
    //assert!(dir.jws(&pkey, true).is_ok());
}

#[test]
#[ignore]
fn test_v2_account_registration() {
    let dir = libs::v2::AcmeAuthDirectory::from_url(LETS_ENCRYPT_V2_STAGING_DIRECTORY_URL).unwrap();
    assert!(dir.account_registration()
        .email("example@example.org")
        .private_key_from_file("tests/data/user.key")
        .unwrap()
        .register()
        .is_ok());
}

#[test]
fn test_v1_directory() {
    assert!(libs::v1::Directory::lets_encrypt().is_ok());

    let dir = libs::v1::Directory::from_url(LETS_ENCRYPT_V1_STAGING_DIRECTORY_URL).unwrap();
    assert!(dir.url_for("new-reg").is_some());
    assert!(dir.url_for("new-authz").is_some());
    assert!(dir.url_for("new-cert").is_some());

    assert!(!dir.get_nonce().unwrap().is_empty());

    let pkey = gen_key().unwrap();
    assert!(dir.jwk(&pkey).is_ok());
    assert!(dir.jws(&pkey, true).is_ok());
}

#[test]
fn test_v1_account_registration() {
    //let _ = env_logger::init();
    let dir = libs::v1::Directory::from_url(LETS_ENCRYPT_V1_STAGING_DIRECTORY_URL).unwrap();
    assert!(dir.account_registration()
        .pkey_from_file("tests/data/user.key")
        .unwrap()
        .register()
        .is_ok());
}

#[test]
fn test_v1_authorization() {
    let _ = env_logger::init();
    let account = testor::v1::test_acc(LETS_ENCRYPT_V1_STAGING_DIRECTORY_URL).unwrap();
    let auth = account.authorization("example.com").unwrap();
    assert!(!auth.0.is_empty());
    assert!(auth.get_challenge("http").is_some());
    assert!(auth.get_http_challenge().is_some());
    assert!(auth.get_dns_challenge().is_some());
    //assert!(auth.get_tls_sni_challenge().is_some());

    for challenge in auth.0 {
        assert!(!challenge.ctype.is_empty());
        assert!(!challenge.url.is_empty());
        assert!(!challenge.token.is_empty());
        assert!(!challenge.key_authorization.is_empty());
    }
}

// This test requires properly configured domain name and a http server
// It will read TEST_DOMAIN and TEST_PUBLIC_DIR environment variables
#[test]
#[ignore]
fn test_v1_sign_certificate() {
    use std::env;
    let _ = env_logger::init();
    let account = testor::v1::test_acc(LETS_ENCRYPT_V1_STAGING_DIRECTORY_URL).unwrap();
    let auth = account
        .authorization(&env::var("TEST_DOMAIN").unwrap())
        .unwrap();
    let http_challenge = auth.get_http_challenge().unwrap();
    assert!(http_challenge
        .save_key_authorization(&env::var("TEST_PUBLIC_DIR").unwrap())
        .is_ok());
    assert!(http_challenge.validate().is_ok());
    let cert = account
        .certificate_signer(&[&env::var("TEST_DOMAIN").unwrap()])
        .sign_certificate()
        .unwrap();
    account.revoke_certificate(cert.cert()).unwrap();
}