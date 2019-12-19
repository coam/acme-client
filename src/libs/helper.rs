use std::path::Path;
use std::fs::File;
use std::io::Read;
use openssl;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::{X509, X509Req, X509Name, X509Ref};
use openssl::x509::extension::SubjectAlternativeName;
use openssl::stack::Stack;
use openssl::hash::MessageDigest;
use libs::error::Result;

/// Default bit lenght for RSA keys and `X509_REQ`
const BIT_LENGTH: u32 = 2048;

/// Generates new PKey.
pub fn gen_key() -> Result<PKey<openssl::pkey::Private>> {
    let rsa = Rsa::generate(BIT_LENGTH)?;
    let key = PKey::from_rsa(rsa)?;
    Ok(key)
}


/// base64 Encoding with URL and Filename Safe Alphabet.
pub fn b64(data: &[u8]) -> String {
    ::base64::encode_config(data, ::base64::URL_SAFE_NO_PAD)
}


/// Reads PKey from Path.
pub fn read_private_key<P: AsRef<Path>>(path: P) -> Result<PKey<openssl::pkey::Private>> {
    let mut file = File::open(path)?;
    let mut content = Vec::new();
    file.read_to_end(&mut content)?;
    let key = PKey::private_key_from_pem(&content)?;
    Ok(key)
}


/// Generates X509Req (CSR) from domain names.
///
/// This function will generate a CSR and sign it with PKey.
///
/// Returns X509Req and PKey used to sign X509Req.
pub fn gen_csr(private_key: &PKey<openssl::pkey::Private>, domains: &[&str]) -> Result<X509Req> {
    if domains.is_empty() {
        return Err("You need to supply at least one or more domain names".into());
    }

    let mut builder = X509Req::builder()?;
    let name = {
        let mut name = X509Name::builder()?;
        name.append_entry_by_text("CN", domains[0])?;
        name.build()
    };
    builder.set_subject_name(&name)?;

    // if more than one domain name is supplied
    // add them as SubjectAlternativeName
    if domains.len() > 1 {
        let san_extension = {
            let mut san = SubjectAlternativeName::new();
            for domain in domains.iter() {
                san.dns(domain);
            }
            san.build(&builder.x509v3_context(None))?
        };
        let mut stack = Stack::new()?;
        stack.push(san_extension)?;
        builder.add_extensions(&stack)?;
    }

    builder.set_pubkey(&private_key)?;
    builder.sign(private_key, MessageDigest::sha256())?;

    Ok(builder.build())
}

/// load a signed certificate from pem formatted file
pub fn get_certificate_from_file<P: AsRef<Path>>(path: P) -> Result<X509> {
    let content = {
        let mut file = File::open(path)?;
        let mut content = Vec::new();
        file.read_to_end(&mut content)?;
        content
    };
    let cert = X509::from_pem(&content)?;
    Ok(cert)
}