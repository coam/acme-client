//! Easy to use [Let's Encrypt](https://letsencrypt.org/) compatible
//! Automatic Certificate Management Environment (ACME) client.
//!
//! You can use acme-client library by adding following lines to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! acme-client = "0.5"
//! ```
//!
//! By default `acme-client` will build CLI. You can disable this with:
//!
//! ```toml
//! [dependencies.acme-client]
//! version = "0.5"
//! default-features = false
//! ```
//!
//! See <https://github.com/onur/acme-client> for CLI usage.
//!
//! ## API overview
//!
//! To successfully sign a SSL certificate for a domain name, you need to identify ownership of
//! your domain. You can also identify and sign certificate for multiple domain names and
//! explicitly use your own private keys and certificate signing request (CSR),
//! otherwise this library will generate them. Basic usage of `acme-client`:
//!
//! ```rust,no_run
//! # use acme_client::libs::error::Result;
//! # fn try_main() -> Result<()> {
//! use acme_client::libs::v2::Directory;
//!
//! let directory = Directory::lets_encrypt()?;
//! let account = directory.account_registration().register()?;
//!
//! // Create a identifier authorization for example.com
//! let authorization = account.authorization("example.com")?;
//!
//! // Validate ownership of example.com with http challenge
//! let http_challenge = authorization.get_http_challenge().ok_or("HTTP challenge not found")?;
//! http_challenge.save_key_authorization("/var/www")?;
//! http_challenge.validate()?;
//!
//! let cert = account.certificate_signer(&["example.com"]).sign_certificate()?;
//! cert.save_signed_certificate("certificate.pem")?;
//! cert.save_private_key("certificate.key")?;
//! # Ok(()) }
//! # fn main () { try_main().unwrap(); }
//! ```
//!
//! `acme-client` supports signing a certificate for multiple domain names with SAN. You need to
//! validate ownership of each domain name:
//!
//! ```rust,no_run
//! # use acme_client::libs::error::Result;
//! # fn try_main() -> Result<()> {
//! use acme_client::libs::v2::Directory;
//!
//! let directory = Directory::lets_encrypt()?;
//! let account = directory.account_registration().register()?;
//!
//! let domains = ["example.com", "example.org"];
//!
//! for domain in domains.iter() {
//!     let authorization = account.authorization(domain)?;
//!     // ...
//! }
//!
//! let cert = account.certificate_signer(&domains).sign_certificate()?;
//! cert.save_signed_certificate("certificate.pem")?;
//! cert.save_private_key("certificate.key")?;
//! # Ok(()) }
//! # fn main () { try_main().unwrap(); }
//! ```
//!
//! ## Account registration
//!
//! ```rust,no_run
//! # use acme_client::libs::error::Result;
//! # fn try_main() -> Result<()> {
//! use acme_client::libs::v2::Directory;
//!
//! let directory = Directory::lets_encrypt()?;
//! let account = directory.account_registration()
//!                        .email("example@example.org")
//!                        .register()?;
//! # Ok(()) }
//! # fn main () { try_main().unwrap(); }
//! ```
//!
//! Contact email address is optional. You can also use your own private key during
//! registration. See [AccountRegistration](struct.AccountRegistration.html) helper for more
//! details.
//!
//! If you already registed with your own keys before, you still need to use
//! [`register`](struct.AccountRegistration.html#method.register) method,
//! in this case it will identify your user account instead of creating a new one.
//!
//!
//! ## Identifying ownership of domain name
//!
//! Before sending a certificate signing request to an ACME server, you need to identify ownership
//! of domain names you want to sign a certificate for. To do that you need to create an
//! Authorization object for a domain name and fulfill at least one challenge (http or dns for
//! Let's Encrypt).
//!
//! To create an Authorization object for a domain:
//!
//! ```rust,no_run
//! # use acme_client::libs::error::Result;
//! # fn try_main() -> Result<()> {
//! use acme_client::libs::v2::Directory;
//! # let directory = Directory::lets_encrypt().unwrap();
//! # // Use staging directory for doc test
//! # let directory = Directory::from_url("https://acme-staging.api.letsencrypt.org/directory")
//! #   .unwrap();
//! # let account = directory.account_registration().register().unwrap();
//! let authorization = account.authorization("example.com")?;
//! # Ok(()) }
//! # fn main () { try_main().unwrap(); }
//! ```
//!
//! [Authorization](struct.Authorization.html) object will contain challenges created by
//! ACME server. You can create as many Authorization object as you want to verify ownership
//! of the domain names. For example if you want to sign a certificate for
//! `example.com` and `example.org`:
//!
//! ```rust,no_run
//! # use acme_client::libs::error::Result;
//! # fn try_main() -> Result<()> {
//! use acme_client::libs::v2::Directory;
//! # let directory = Directory::lets_encrypt().unwrap();
//! # let account = directory.account_registration().register().unwrap();
//! let domains = ["example.com", "example.org"];
//! for domain in domains.iter() {
//!     let authorization = account.authorization(domain)?;
//!     // ...
//! }
//! # Ok(()) }
//! # fn main () { try_main().unwrap(); }
//! ```
//!
//! ### Identifier validation challenges
//!
//! When you send authorization request to an ACME server, it will generate
//! identifier validation challenges to provide assurence that an account holder is also
//! the entity that controls an identifier.
//!
//! #### HTTP challenge
//!
//! With HTTP validation, the client in an ACME transaction proves its
//! control over a domain name by proving that it can provision resources
//! on an HTTP server that responds for that domain name.
//!
//! `acme-client` has
//! [`save_key_authorization`](struct.Challenge.html#method.save_key_authorization) method
//! to save vaditation file to a public directory. This directory must be accessible to outside
//! world.
//!
//! ```rust,no_run
//! # use acme_client::libs::error::Result;
//! # fn try_main() -> Result<()> {
//! use acme_client::libs::v2::Directory;
//! # let directory = Directory::lets_encrypt()?;
//! # let account = directory.account_registration()
//! #                        .pkey_from_file("tests/data/user.key")?  // use test key for doc test
//! #                        .register()?;
//! let authorization = account.authorization("example.com")?;
//! let http_challenge = authorization.get_http_challenge().ok_or("HTTP challenge not found")?;
//!
//! // This method will save key authorization into
//! // /var/www/.well-known/acme-challenge/ directory.
//! http_challenge.save_key_authorization("/var/www")?;
//!
//! // Validate ownership of example.com with http challenge
//! http_challenge.validate()?;
//! # Ok(()) }
//! # fn main () { try_main().unwrap(); }
//! ```
//!
//! During validation, ACME server will check
//! `http://example.com/.well-known/acme-challenge/{token}` to identify ownership of domain name.
//! You need to make sure token is publicly accessible.
//!
//! #### DNS challenge:
//!
//! The DNS challenge requires the client to provision a TXT record containing a designated
//! value under a specific validation domain name.
//!
//! `acme-client` can generated this value with
//! [`signature`](struct.Challenge.html#method.signature) method.
//!
//! The user constructs the validation domain name by prepending the label "_acme-challenge"
//! to the domain name being validated, then provisions a TXT record with the digest value under
//! that name. For example, if the domain name being validated is "example.com", then the client
//! would provision the following DNS record:
//!
//! ```text
//! _acme-challenge.example.com: dns_challenge.signature()
//! ```
//!
//! Example validation with DNS challenge:
//!
//! ```rust,no_run
//! # use acme_client::libs::error::Result;
//! # fn try_main() -> Result<()> {
//! use acme_client::libs::v2::Directory;
//! # let directory = Directory::lets_encrypt()?;
//! # let account = directory.account_registration()
//! #                        .pkey_from_file("tests/data/user.key")?  // use test key for doc test
//! #                        .register()?;
//! let authorization = account.authorization("example.com")?;
//! let dns_challenge = authorization.get_dns_challenge().ok_or("DNS challenge not found")?;
//! let signature = dns_challenge.signature()?;
//!
//! // User creates a TXT record for _acme-challenge.example.com with the value of signature.
//!
//! // Validate ownership of example.com with DNS challenge
//! dns_challenge.validate()?;
//! # Ok(()) }
//! # fn main () { try_main().unwrap(); }
//! ```
//!
//! ## Signing a certificate
//!
//! After validating all the domain names you can send a sign certificate request. `acme-client`
//! provides [`CertificateSigner`](struct.CertificateSigner.html) helper for this. You can
//! use your own key and CSR or you can let `CertificateSigner` to generate them for you.
//!
//! ```rust,no_run
//! # use acme_client::libs::error::Result;
//! # fn try_main() -> Result<()> {
//! use acme_client::libs::v2::Directory;
//! # let directory = Directory::lets_encrypt()?;
//! # let account = directory.account_registration().register()?;
//! let domains = ["example.com", "example.org"];
//!
//! // ... validate ownership of domain names
//!
//! let certificate_signer = account.certificate_signer(&domains);
//! let cert = certificate_signer.sign_certificate()?;
//! cert.save_signed_certificate("certificate.pem")?;
//! cert.save_private_key("certificate.key")?;
//! # Ok(()) }
//! # fn main () { try_main().unwrap(); }
//! ```
//!
//! ## Revoking a signed certificate
//!
//! You can use `revoke_certificate` or `revoke_certificate_from_file` methods to revoke a signed
//! certificate. You need to register with the same private key you registered before to
//! successfully revoke a signed certificate. You can also use private key used to generate CSR.
//!
//! ```rust,no_run
//! # use acme_client::libs::error::Result;
//! # fn try_main() -> Result<()> {
//! use acme_client::libs::v2::Directory;
//! # let directory = Directory::lets_encrypt()?;
//! let account = directory.account_registration()
//!                        .pkey_from_file("user.key")?
//!                        .register()?;
//! account.revoke_certificate_from_file("certificate.pem")?;
//! # Ok(()) }
//! # fn main () { try_main().unwrap(); }
//! ```
//!
//! ## References
//!
//! * [IETF ACME draft](https://tools.ietf.org/html/draft-ietf-acme-acme-05)
//! * [Let's Encrypt ACME divergences](https://github.com/letsencrypt/boulder/blob/9c1e8e6764c1de195db6467057e0d148608e411d/docs/acme-divergences.md)

use std::path::Path;
use std::fs::File;
use std::io::{Read, Write};
use std::collections::HashMap;

use openssl::sign::Signer;
use openssl::hash::{hash, MessageDigest};
use openssl::pkey::PKey;
use openssl::x509::{X509, X509Req};

use reqwest::{Client, StatusCode};
use reqwest::header::HeaderMap;

use libs::helper::{gen_key, b64, read_pkey, gen_csr};
use libs::error::{Result, ErrorKind};

//use helper::{gen_key, b64, read_pkey, gen_csr};
//use error::{Result, ErrorKind};

// 设置环境配置...
//use std::env;
//use log;
//use env_logger;
//use pretty_env_logger;

use serde_json::{Value, from_str, to_string, to_value};
use serde::Serialize;

/// Default Let's Encrypt directory URL to configure client.
pub const LETS_ENCRYPT_DIRECTORY_URL: &'static str = "https://acme-v02.api.letsencrypt.org/directory";
/// Default Let's Encrypt agreement URL used in account registration.
pub const LETS_ENCRYPT_AGREEMENT_URL: &'static str = "https://letsencrypt.org/documents/LE-SA-v2.2-November-15-2017.pdf";
/// Default Let's Encrypt intermediate certificate URL to chain when needed.
pub const LETS_ENCRYPT_INTERMEDIATE_CERT_URL: &'static str = "https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem";

/// Default bit lenght for RSA keys and `X509_REQ`
//const BIT_LENGTH: u32 = 2048;

/// Directory object to configure client. Main entry point of `acme-client`.
///
/// See [section-6.1.1](https://tools.ietf.org/html/draft-ietf-acme-acme-05#section-6.1.1)
/// for more details.
pub struct Directory {
    /// Base URL of directory
    url: String,
    directory: Value,
}

/// Registered account object.
///
/// Every operation requires a registered account. To register an `Account` you can use
/// `Directory::register_account` method.
///
/// See [AccountRegistration](struct.AccountRegistration.html) helper for more details.
pub struct Account {
    directory: Directory,
    account_url: String,
    pkey: PKey<openssl::pkey::Private>,
}


/// Helper to register an account.
pub struct AccountRegistration {
    directory: Directory,
    pkey: Option<PKey<openssl::pkey::Private>>,
    email: Option<String>,
    contact: Option<Vec<String>>,
    agreement: Option<String>,
}

/// Helper to sign a certificate.
pub struct CertificateSigner<'a> {
    account: &'a Account,
    domains: &'a [&'a str],
    pkey: Option<PKey<openssl::pkey::Private>>,
    csr: Option<X509Req>,
}


/// A signed certificate.
pub struct SignedCertificate {
    cert: X509,
    csr: X509Req,
    pkey: PKey<openssl::pkey::Private>,
}


/// Identifier authorization object.
pub struct Authorization<'a>(pub Vec<Challenge<'a>>);


/// A verification challenge.
pub struct Challenge<'a> {
    pub account: &'a Account,
    /// Type of verification challenge. Usually `http-01`, `dns-01` for letsencrypt.
    pub ctype: String,
    /// URL to trigger challenge.
    pub url: String,
    /// Challenge token.
    pub token: String,
    /// Key authorization.
    pub key_authorization: String,
}


impl Directory {
    /// Creates a Directory from
    /// [`LETS_ENCRYPT_DIRECTORY_URL`](constant.LETS_ENCRYPT_DIRECTORY_URL.html).
    pub fn lets_encrypt() -> Result<Directory> {
        Directory::from_url(LETS_ENCRYPT_DIRECTORY_URL)
    }

    /// Creates a Directory from directory URL.
    ///
    /// Example directory for testing `acme-client` crate with staging API:
    ///
    /// ```rust
    /// # use acme_client::libs::error::Result;
    /// # fn try_main() -> Result<()> {
    /// use acme_client::libs::v2::Directory;
    /// let dir = Directory::from_url("https://acme-staging.api.letsencrypt.org/directory")?;
    /// # Ok(()) }
    /// # fn main () { try_main().unwrap(); }
    /// ```
    pub fn from_url(url: &str) -> Result<Directory> {
        // 设置日志等级...
        // Error -> Warn -> Info -> Debug -> Trace
        // RUST_LOG=info cargo run
        //env::set_var("RUST_LOG", "run_s");
        //env::set_var("RUST_LOG", "coam_s=info");

        //env_logger::init();
        //pretty_env_logger::init();

        info!("[签发域名证书环境][ACME][from_url()][LETS_ENCRYPT_DIRECTORY_URL][url: {:?}]", url);

        let client = Client::new();
        let mut res = client.get(url).send()?;
        let mut content = String::new();
        res.read_to_string(&mut content)?;
        Ok(Directory {
            url: url.to_owned(),
            directory: from_str(&content)?,
        })
    }

    /// Returns url for the resource.
    pub fn url_for(&self, resource: &str) -> Option<&str> {
        self.directory
            .as_object()
            .and_then(|o| o.get(resource))
            .and_then(|k| k.as_str())
    }

    /// Consumes directory and creates new AccountRegistration.
    ///
    /// AccountRegistration is used to register an account.
    ///
    /// ```rust,no_run
    /// # use acme_client::libs::error::Result;
    /// # fn try_main() -> Result<()> {
    /// use acme_client::libs::v2::Directory;
    ///
    /// let directory = Directory::lets_encrypt()?;
    /// let account = directory.account_registration()
    ///                        .email("example@example.org")
    ///                        .register()?;
    /// # Ok(()) }
    /// # fn main () { try_main().unwrap(); }
    /// ```
    pub fn account_registration(self) -> AccountRegistration {
        AccountRegistration {
            directory: self,
            pkey: None,
            email: None,
            contact: None,
            agreement: None,
        }
    }

    /// Gets nonce header from directory.
    ///
    /// This function will try to look for `new-nonce` key in directory if it doesn't exists
    /// it will try to get nonce header from directory url.
    pub fn get_nonce(&self) -> Result<String> {
        let url = self.url_for("newNonce").unwrap_or(&self.url);
        let client = Client::new();
        let res = client.get(url).send()?;
//        res.headers()
//            .get::<hyperx::ReplayNonce>()
//            .ok_or("Replay-Nonce header not found".into())
//            .and_then(|nonce| Ok(nonce.as_str().to_string()))

        res.headers()
            .get("Replay-Nonce")
            .ok_or("Replay-Nonce header not found".into())
            .and_then(|nonce| nonce.to_str().map_err(|_| "Nonce header value contains invalid characters".into()))
            .map(|nonce| nonce.to_string())
    }

    /// Makes a new post request to directory, signs payload with pkey.
    ///
    /// Returns status code and Value object from reply.
    fn request<T: Serialize>(&self, pkey: &PKey<openssl::pkey::Private>, resource: &str, payload: T, kid: Option<String>) -> Result<(StatusCode, Value, HeaderMap)> {
        let mut json = to_value(&payload)?;

        //let resource_json: Value = to_value(resource)?;
        //json.as_object_mut().and_then(|obj| obj.insert("resource".to_owned(), resource_json));

        debug!("[发起请求->request()][resource: {:?}][json: {:?}]", resource, json);

        // 获取请求的url
        let url = self.url_for(resource).ok_or(format!("URL for resource: {} not found", resource))?;

        // 获取 jws
        let jws = self.jws(url, pkey, json, kid)?;

        debug!("[发起请求->request()][url: {:?}][jws: {:?}]", url, jws);

        // 添加 [application/jose+json] 请求头
        let mut headers = HeaderMap::new();
        //headers.set(ContentType::json());
        headers.insert(reqwest::header::CONTENT_TYPE, "application/jose+json".parse().unwrap());

        // 请求客户端...
        let client = Client::new();
        let mut res = client
            .post(url)
            .headers(headers)
            //.body(&jws[..])
            .body(jws)
            .send()?;

        let res_json = {
            let mut res_content = String::new();
            res.read_to_string(&mut res_content)?;
            if !res_content.is_empty() {
                from_str(&res_content)?
            } else {
                to_value(true)?
            }
        };

        // 响应头...
        let resp_headers = res.headers();

        Ok((res.status(), res_json, resp_headers.clone()))
    }

    /// Makes a Flattened JSON Web Signature from payload
    pub fn jws<T: Serialize>(&self, url: &str, pkey: &PKey<openssl::pkey::Private>, payload: T, kid: Option<String>) -> Result<String> {
        let nonce = self.get_nonce()?;
        let mut data: HashMap<String, Value> = HashMap::new();

        // header: 'alg': 'RS256', 'jwk': { e, n, kty }
        let mut header: HashMap<String, Value> = HashMap::new();
        header.insert("url".to_owned(), to_value(url)?);
        header.insert("alg".to_owned(), to_value("RS256")?);
        header.insert("nonce".to_owned(), to_value(nonce)?);

        // 设置验证方式...
        if let Some(_kid) = kid {
            header.insert("kid".to_owned(), to_value(_kid)?);
        } else {
            header.insert("jwk".to_owned(), self.jwk(pkey)?);
        }
        //data.insert("header".to_owned(), to_value(&header)?);

        let mut json = to_value(&payload)?;
        debug!("[发起请求->request()->jws()][payload: {:?}]", json);
        debug!("[发起请求->request()->jws()][protected=>header: {:?}]", header);

        // payload: b64 of payload
        let payload = to_string(&payload)?;
        let payload64 = b64(&payload.into_bytes());
        data.insert("payload".to_owned(), to_value(&payload64)?);

        // protected: base64 of header + nonce
        let protected64 = b64(&to_string(&header)?.into_bytes());
        data.insert("protected".to_owned(), to_value(&protected64)?);

        // signature: b64 of hash of signature of {proctected64}.{payload64}
        data.insert("signature".to_owned(), {
            let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
            signer.update(&format!("{}.{}", protected64, payload64).into_bytes())?;
            to_value(b64(&signer.sign_to_vec()?))?
        });

        debug!("[发起请求->request()->jws()][data: {:?}]", data);

        let json_str = to_string(&data)?;
        Ok(json_str)
    }

    /// Returns jwk field of jws header
    pub fn jwk(&self, pkey: &PKey<openssl::pkey::Private>) -> Result<Value> {
        let rsa = pkey.rsa()?;
        let mut jwk: HashMap<String, String> = HashMap::new();
        jwk.insert("e".to_owned(), b64(&rsa.e().to_vec()));
        jwk.insert("kty".to_owned(), "RSA".to_owned());
        jwk.insert("n".to_owned(), b64(&rsa.n().to_vec()));
        Ok(to_value(jwk)?)
    }
}

// 账户授权响应数据...
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccountAuthData {
    pub identifier: OrderIdentifier,
    status: String,
    expires: String,
    pub challenges: Vec<AccountAuthChallenge>,
}

// Challenge 挑战...
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccountAuthChallenge {
    //r#type: String,
    #[serde(rename = "type")]
    pub types: String,
    pub status: String,
    pub url: String,
    pub token: String,
    pub wildcard: Option<bool>,
    #[serde(rename = "validationRecord")]
    pub validation_record: Option<Vec<AccountAuthChallengeValidationRecord>>,
    // 授权签名...
    pub key_authorization: Option<String>,
    pub auth_challenge_token: Option<String>,
}

// Challenge 挑战...
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccountAuthChallengeValidationRecord {
    hostname: String,
}

impl Account {
    /// Creates a new identifier authorization object for domain
    //pub fn get_acme_order_authorization<'a>(&'a self, order: &OrderData) -> Result<Authorization<'a>> {
    pub fn get_acme_order_authorization(&self, order: &OrderData) -> Result<Vec<AccountAuthData>> {
        info!("[循环验证 ACME 订单] -> Sending authorization request for order: {:?}", order);
        //info!("Sending identifier authorization request for {}", domain);


//        let mut map = HashMap::new();
//        map.insert("identifier".to_owned(), {
//            let mut map = HashMap::new();
//            map.insert("type".to_owned(), "dns".to_owned());
//            map.insert("value".to_owned(), domain.to_owned());
//            map
//        });
//        let (status, resp, resp_headers) = self.directory().request(self.pkey(), "new-authz", map, None)?;
//
//        if status != StatusCode::CREATED {
//            return Err(ErrorKind::AcmeServerError(resp).into());
//        }

        // 挑战列表...
        //let mut challenges = Vec::new();

        // 授权列表...
        let mut acme_order_auth_list = Vec::new();

        // 循环授权验证...
        for authorization in &order.authorizations {
            println!("\n");
            info!("[开始发起 ACME 订单验证挑战] -> For send authorization request for [authorization: {:?}]", authorization);

            // 发起授权验证...
            let client = Client::new();
            //let mut resp = client.get(authorization).send()?;
            let mut resp = client.get(authorization).send()?;

            // [How do you make a GET request in Rust?](https://stackoverflow.com/questions/43222429/how-do-you-make-a-get-request-in-rust)
            // copy the response body directly to stdout
            //std::io::copy(&mut resp, &mut std::io::stdout())?;

            debug!("[####################][+++][status: {:?}]", resp.status());
            debug!("[####################][+++]Headers:\n{:?}", resp.headers());
            debug!("[####################][+++]resp: \n{:?}", resp);

            let mut account_auth_data: AccountAuthData = resp.json()?;
            debug!("[####################][+++]resp.account_auth_data: \n{:?}", account_auth_data);

            // 循环挑战...
            for auth_challenge in &mut account_auth_data.challenges {
                // 获取挑战...
                let token = auth_challenge.token.clone();
                let types = auth_challenge.types.clone();
                let url = auth_challenge.url.clone();

                // This seems really cryptic but it's not
                // https://tools.ietf.org/html/draft-ietf-acme-acme-05#section-7.1
                // key-authz = token || '.' || base64url(JWK\_Thumbprint(accountKey))
                let thumbprint = b64(&hash(MessageDigest::sha256(), &to_string(&self.directory().jwk(self.pkey())?)?.into_bytes())?);
                let key_authorization = format!("{}.{}", auth_challenge.token, thumbprint);
                //let challenge_token = b64(&hash(MessageDigest::sha256(), key_authorization.as_bytes())?);
                debug!("authorization challenge info: [thumbprint: {:?}]", thumbprint);
                debug!("authorization challenge info: [key_authorization: {:?}]", key_authorization);

                // 获取挑战签名...
                let challenge = Challenge {
                    account: self,
                    ctype: types,
                    url: url,
                    token: token,
                    key_authorization: key_authorization.clone(),
                };
                let auth_challenge_token = challenge.signature().unwrap();
                debug!("authorization challenge info: [auth_challenge_token: {:?}]", auth_challenge_token);

                // 保存授权...
                auth_challenge.key_authorization = Some(key_authorization);
                auth_challenge.auth_challenge_token = Some(auth_challenge_token);
            }

            // 推入授权列表...
            acme_order_auth_list.push(account_auth_data);

            //info!("authorization challenge: [challenge: {:?}]", challenge);
            //let (status, resp, resp_headers) = self.directory().request(self.pkey(), "new-authz", map, None)?;
            //info!("authorization request Results: [status: {:?}]", status);
        }

//        for challenge in resp.as_object()
//            .and_then(|obj| obj.get("challenges"))
//            .and_then(|c| c.as_array())
//            .ok_or("No challenge found")? {
//            let obj = challenge
//                .as_object()
//                .ok_or("Challenge object not found")?;
//
//            let ctype = obj.get("type")
//                .and_then(|t| t.as_str())
//                .ok_or("Challenge type not found")?
//                .to_owned();
//            let uri = obj.get("uri")
//                .and_then(|t| t.as_str())
//                .ok_or("URI not found")?
//                .to_owned();
//            let token = obj.get("token")
//                .and_then(|t| t.as_str())
//                .ok_or("Token not found")?
//                .to_owned();
//
//            // This seems really cryptic but it's not
//            // https://tools.ietf.org/html/draft-ietf-acme-acme-05#section-7.1
//            // key-authz = token || '.' || base64url(JWK\_Thumbprint(accountKey))
//            let key_authorization = format!("{}.{}",
//                                            token,
//                                            b64(&hash(MessageDigest::sha256(),
//                                                      &to_string(&self.directory()
//                                                          .jwk(self.pkey())?)?
//                                                          .into_bytes())?));
//
//            let challenge = Challenge {
//                account: self,
//                ctype: ctype,
//                url: uri,
//                token: token,
//                key_authorization: key_authorization,
//            };
//            challenges.push(challenge);
//        }

        //Ok(Authorization(challenges))
        Ok(acme_order_auth_list)
    }

    /// Revokes a signed certificate from pem formatted file
    pub fn get_certificate_from_file<P: AsRef<Path>>(&self, path: P) -> Result<X509> {
        let content = {
            let mut file = File::open(path)?;
            let mut content = Vec::new();
            file.read_to_end(&mut content)?;
            content
        };
        let cert = X509::from_pem(&content)?;
        Ok(cert)
    }

    /// Creates a new `CertificateSigner` helper to sign a certificate for list of domains.
    ///
    /// `domains` must be list of the domain names you want to sign a certificate for.
    /// Currently there is no way to retrieve subject alt names from a X509Req.
    ///
    /// You can additionally use your own private key and CSR.
    /// See [`CertificateSigner`](struct.CertificateSigner.html) for details.
    pub fn certificate_signer<'a>(&'a self, domains: &'a [&'a str]) -> CertificateSigner<'a> {
        CertificateSigner {
            account: self,
            domains: domains,
            pkey: None,
            csr: None,
        }
    }

    /// Revokes a signed certificate from pem formatted file
    pub fn revoke_certificate_from_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = {
            let mut file = File::open(path)?;
            let mut content = Vec::new();
            file.read_to_end(&mut content)?;
            content
        };
        let cert = X509::from_pem(&content)?;
        self.revoke_certificate(&cert)
    }

    /// Revokes a signed certificate
    pub fn revoke_certificate(&self, cert: &X509) -> Result<()> {
        let (status, resp, resp_headers) = {
            let mut map = HashMap::new();
            map.insert("certificate".to_owned(), b64(&cert.to_der()?));

            self.directory().request(self.pkey(), "revoke-cert", map, None)?
        };

        match status {
            StatusCode::OK => info!("Certificate successfully revoked"),
            StatusCode::CONFLICT => warn!("Certificate already revoked"),
            _ => return Err(ErrorKind::AcmeServerError(resp).into()),
        }

        Ok(())
    }

    /// Writes account private key to a writer
    pub fn write_private_key<W: Write>(&self, writer: &mut W) -> Result<()> {
        Ok(writer.write_all(&self.pkey().private_key_to_pem_pkcs8()?)?)
    }

    /// Saves account private key to a file
    pub fn save_private_key<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut file = File::create(path)?;
        self.write_private_key(&mut file)
    }

    /// Returns a reference to account private key
    pub fn pkey(&self) -> &PKey<openssl::pkey::Private> {
        &self.pkey
    }

    /// Returns a reference to directory used to create account
    pub fn directory(&self) -> &Directory {
        &self.directory
    }

    // 创建订单构造器...
    pub fn order_creator(&self) -> OrderCreator {
        OrderCreator {
            order_identifiers: None,
        }
    }
}


impl AccountRegistration {
    /// Sets contact email address
    pub fn email(mut self, email: &str) -> AccountRegistration {
        self.email = Some(email.to_owned());
        self
    }

    /// Sets contact details such as telephone number (Let's Encrypt only supports email address).
    pub fn contact(mut self, contact: &[&str]) -> AccountRegistration {
        self.contact = Some(contact.iter().map(|c| c.to_string()).collect());
        self
    }

    /// Sets agreement url,
    /// [`LETS_ENCRYPT_AGREEMENT_URL`](constant.LETS_ENCRYPT_AGREEMENT_URL.html)
    /// will be used during registration if it's not set.
    pub fn agreement(mut self, url: &str) -> AccountRegistration {
        self.agreement = Some(url.to_owned());
        self
    }

    /// Sets account private key. A new key will be generated if it's not set.
    pub fn pkey(mut self, pkey: PKey<openssl::pkey::Private>) -> AccountRegistration {
        self.pkey = Some(pkey);
        self
    }

    /// Sets PKey from a PEM formatted file.
    pub fn pkey_from_file<P: AsRef<Path>>(mut self, path: P) -> Result<AccountRegistration> {
        self.pkey = Some(read_pkey(path)?);
        Ok(self)
    }

    /// Registers an account.
    ///
    /// A PKey will be generated if it doesn't exists.
    pub fn register(self) -> Result<Account> {
        debug!("[发起注册账户流程:v2]Registering account");

        let mut map = HashMap::new();
        //map.insert("agreement".to_owned(), to_value(self.agreement.unwrap_or(LETS_ENCRYPT_AGREEMENT_URL.to_owned()))?);
        map.insert("termsOfServiceAgreed".to_owned(), to_value(true)?);
        if let Some(mut contact) = self.contact {
            //if let Some(email) = self.email {
            //    contact.push(format!("mailto:{}", email));
            //}
            map.insert("contact".to_owned(), to_value(contact)?);
        }
        if let Some(email) = self.email {
            map.insert("email".to_owned(), to_value(email)?);
        }

        info!("[发送账户注册请求参数][resources: newAccount][map: {:?}]", map);

        let pkey = self.pkey.unwrap_or(gen_key()?);

        let (status, resp, resp_headers) = self.directory.request(&pkey, "newAccount", map, None)?;

        debug!("[请求账户注册结果][status: {:?}][resp: {:?}][resp_headers: {:?}]", status, resp, resp_headers);

        match status {
            StatusCode::OK => info!("[账户注册成功] -> StatusCode::OK - User successfully registered!"),
            StatusCode::CREATED => info!("[账户注册成功] -> StatusCode::CREATED - User successfully registered!"),
            StatusCode::CONFLICT => info!("[账户注册成功] -> StatusCode::CONFLICT - User already registered!"),
            _ => return Err(ErrorKind::AcmeServerError(resp).into()),
        };

        // 账户地址...
        let account_url = resp_headers.get("location").unwrap();

        Ok(Account {
            directory: self.directory,
            account_url: String::from(account_url.to_str().unwrap()),
            pkey: pkey,
        })
    }
}

/// Helper to create an order.
//#[derive(Serialize, Deserialize, Debug)]
pub struct OrderCreator {
    order_identifiers: Option<Vec<OrderIdentifier>>,
}

// 订单数据
#[derive(Serialize, Deserialize, Debug)]
pub struct OrderData {
    //directory: Directory,
    pub account_url: String,
    pub order_url: String,
    pub finalize_url: String,
    pub certificate: Option<String>,
    //pkey: PKey<openssl::pkey::Private>,
    pub authorizations: Vec<String>,
    pub identifiers: Vec<OrderIdentifier>,
}

// 订单接口数据
#[derive(Serialize, Deserialize, Debug)]
pub struct OrderResponse {
    pub status: String,
    pub finalize: String,
    pub certificate: Option<String>,
    pub expires: String,
    pub authorizations: Vec<String>,
    pub identifiers: Vec<OrderIdentifier>,
}

// DNS 解析记录
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OrderIdentifier {
    #[serde(rename = "type")]
    pub types: String,
    pub value: String,
}

impl OrderCreator {
    /// Sets contact email address
    pub fn identifiers(mut self, order_identifiers: Vec<OrderIdentifier>) -> OrderCreator {
        self.order_identifiers = Some(order_identifiers);
        self
    }

    /// Registers an account.
    ///
    /// A PKey will be generated if it doesn't exists.
    pub fn create(self, account: &Account) -> Result<OrderData> {
        info!("[执行创建订单流程]Creating order");

        let mut map = HashMap::new();

        // 创建订单域名...
        map.insert("identifiers".to_owned(), &self.order_identifiers);

        // 手动创建...
        //let point = vec![
        //    OrderIdentifier {
        //        types: String::from("dns"),
        //        value: String::from("copen.io"),
        //    }, OrderIdentifier {
        //        types: String::from("dns"),
        //        value: String::from("*.copen.io"),
        //    }
        //];
        //let serialized = serde_json::to_string(&point).unwrap();
        //map.insert("identifiers".to_owned(), point);

        // Convert the Point to a JSON string.
        //let serialized = serde_json::to_string(&self.order_identifiers).unwrap();

        info!("[发起创建订单请求参数][resources: createOrder][map: {:?}]", map);

        let pkey = &account.pkey;
        let account_url = &account.account_url;

        let (status, resp, resp_headers) = account.directory().request(&pkey, "newOrder", map, Some(account_url.clone()))?;

        debug!("[创建订单请求结果][status: {:?}][resp: {:?}][resp_headers: {:?}]", status, resp, resp_headers);

        match status {
            StatusCode::OK => info!("[订单创建成功] -> Order successfully ok"),
            StatusCode::CREATED => info!("[订单创建成功] -> Order successfully created"),
            _ => return Err(ErrorKind::AcmeServerError(resp).into()),
        };

        // 解析结构体数据...
        let order_response: OrderResponse = serde_json::from_str(&resp.to_string())?;

        // 账户地址...
        let order_url = resp_headers.get("location").unwrap().to_str().unwrap();

        Ok(OrderData {
            account_url: account_url.clone(),
            order_url: order_url.to_string(),
            finalize_url: order_response.finalize,
            certificate: None,
            authorizations: order_response.authorizations,
            identifiers: order_response.identifiers,
        })
    }
}

impl<'a> CertificateSigner<'a> {
    /// Set PKey of CSR
    pub fn pkey(mut self, pkey: PKey<openssl::pkey::Private>) -> CertificateSigner<'a> {
        self.pkey = Some(pkey);
        self
    }

    /// Load PEM formatted PKey from file
    pub fn pkey_from_file<P: AsRef<Path>>(mut self, path: P) -> Result<CertificateSigner<'a>> {
        self.pkey = Some(read_pkey(path)?);
        Ok(self)
    }

    /// Set CSR to sign
    pub fn csr(mut self, csr: X509Req) -> CertificateSigner<'a> {
        self.csr = Some(csr);
        self
    }

    /// Load PKey and CSR from file
    pub fn csr_from_file<P: AsRef<Path>>(mut self, pkey_path: P, csr_path: P) -> Result<CertificateSigner<'a>> {
        self.pkey = Some(read_pkey(pkey_path)?);
        let content = {
            let mut file = File::open(csr_path)?;
            let mut content = Vec::new();
            file.read_to_end(&mut content)?;
            content
        };
        self.csr = Some(X509Req::from_pem(&content)?);

        Ok(self)
    }

    /// create certificate.
    pub fn create_certificate(mut self) -> Result<CertificateSigner<'a>> {
        // 创建证书...
        let pkey = self.pkey.unwrap_or(gen_key().unwrap());
        let csr = self.csr.unwrap_or(gen_csr(&pkey, self.domains).unwrap());

        // 创建证书...
        self.pkey = Some(pkey);
        self.csr = Some(csr);

        Ok(self)
    }

    /// finalize_order.
    /// CSR and PKey will be generated if it doesn't set or loaded first.
    pub fn finalize_order<'b, 'c>(&'b self, order: &'c mut OrderData) -> Result<&'c OrderData> {
        // 获取请求的url
        //let url = self.account.directory().url_for(resource).ok_or(format!("URL for resource: {} not found", resource))?;
        //let url = &order.order_url;
        let finalize_url = &order.finalize_url;

        // request finalize order...
        let mut map = HashMap::new();
        //map.insert("resource".to_owned(), "new-cert".to_owned());
        //map.insert("resource".to_owned(), resource.to_owned());
        map.insert("csr".to_owned(), b64(&self.csr.as_ref().unwrap().to_der()?));

        // 设置载荷...
        let payload = {
            self.account.directory().jws(finalize_url, self.account.pkey(), map.clone(), Some(self.account.account_url.clone()))?
        };

        debug!("[COAM][####################][+++][finalize_url: {}]", finalize_url);
        debug!("[COAM][####################][+++][payload: {}]", payload);

        // 添加 [application/jose+json] 请求头
        let mut headers = HeaderMap::new();
        //headers.set(ContentType::json());
        headers.insert(reqwest::header::CONTENT_TYPE, "application/jose+json".parse().unwrap());

        // 发起请求...
        let client = Client::new();
        //let jws = self.account.directory().jws(finalize_url, self.account.pkey(), map, Some(self.account.account_url.clone()))?
        let mut res = client
            .post(finalize_url)
            .headers(headers)
            //.body(&jws[..])
            //.body(jws)
            .body(payload)
            .send()?;

        // 读取响应数据
        //let body = res.text()?;
        //info!("[####################][+++]res.body: \n{:?}", body);

        // [How do you make a GET request in Rust?](https://stackoverflow.com/questions/43222429/how-do-you-make-a-get-request-in-rust)
        // copy the response body directly to stdout
        //std::io::copy(&mut res, &mut std::io::stdout())?;

        let mut order_response: OrderResponse = res.json()?;
        debug!("[####################][+++]res.order_response: \n{:?}", order_response);

        // 判断是否经过验证...
        if order_response.status != "valid" {
            panic!("未验证通过!");
        }

        // [How do you make a GET request in Rust?](https://stackoverflow.com/questions/43222429/how-do-you-make-a-get-request-in-rust)
        // copy the response body directly to stdout
        //std::io::copy(&mut res, &mut std::io::stdout())?;

        debug!("[####################][---][status: {:?}]", res.status());
        debug!("[####################][---]Headers:\n{:?}", res.headers());
        debug!("[####################][---]res: \n{:?}", res);

        // 复制证书...
        order.certificate = order_response.certificate;

        Ok(order)
    }

    /// Signs certificate.
    ///
    /// CSR and PKey will be generated if it doesn't set or loaded first.
    pub fn sign_certificate(self, order: &OrderData) -> Result<SignedCertificate> {
        info!("[验证订单签发证书流程] -> Signing certificate");

        // 判断是否经过验证...
        if let Some(certificate_url) = order.certificate.clone() {
            debug!("订单域名验证通过-可请求签发证书!");
        } else {
            panic!("未获取证书文件地址-无法签发证书!");
        }

        debug!("[请求签发订单域名证书] get certificate...");

        let certificate_url = order.certificate.clone().unwrap();

        // 发起请求...
        let client = Client::new();
        let mut res = client.get(certificate_url.as_str()).send()?;

        debug!("[####################][---][status: {:?}]", res.status());
        debug!("[####################][---]Headers:\n{:?}", res.headers());
        debug!("[####################][---]res: \n{:?}", res);

        // [How do you make a GET request in Rust?](https://stackoverflow.com/questions/43222429/how-do-you-make-a-get-request-in-rust)
        // copy the response body directly to stdout
        //std::io::copy(&mut res, &mut std::io::stdout())?;

        //if res.status() != StatusCode::CREATED {
        if res.status() != StatusCode::OK {
            let res_json = {
                let mut res_content = String::new();
                res.read_to_string(&mut res_content)?;
                from_str(&res_content)?
            };
            return Err(ErrorKind::AcmeServerError(res_json).into());
        }

        // 创建证书...
        let mut crt_der = Vec::new();
        res.read_to_end(&mut crt_der)?;

        //let s = String::from_utf8_lossy(&crt_der);
        //info!("[####################][---]result: \n{:?}", s);

        //let cert = X509::from_der(&crt_der)?;
        let cert = X509::from_pem(&crt_der)?;

        info!("[域名证书签发成功]Certificate successfully signed........................................................................................");

        Ok(SignedCertificate {
            cert: cert,
            csr: self.csr.unwrap(),
            pkey: self.pkey.unwrap(),
        })
    }
}


impl SignedCertificate {
    /// Saves signed certificate to a file
    pub fn save_signed_certificate<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut file = File::create(path)?;
        self.write_signed_certificate(&mut file)
    }

    /// Saves intermediate certificate to a file
    ///
    /// You can additionally provide intermediate certificate url, by default it will use
    /// [`LETS_ENCRYPT_INTERMEDIATE_CERT_URL`](constant.LETS_ENCRYPT_INTERMEDIATE_CERT_URL.html).
    pub fn save_intermediate_certificate<P: AsRef<Path>>(&self, url: Option<&str>, path: P) -> Result<()> {
        let mut file = File::create(path)?;
        self.write_intermediate_certificate(url, &mut file)
    }

    /// Saves intermediate certificate and signed certificate to a file
    ///
    /// You can additionally provide intermediate certificate url, by default it will use
    /// [`LETS_ENCRYPT_INTERMEDIATE_CERT_URL`](constant.LETS_ENCRYPT_INTERMEDIATE_CERT_URL.html).
    pub fn save_signed_certificate_and_chain<P: AsRef<Path>>(&self, url: Option<&str>, path: P) -> Result<()> {
        let mut file = File::create(path)?;
        self.write_signed_certificate(&mut file)?;
        self.write_intermediate_certificate(url, &mut file)?;
        Ok(())
    }

    /// Saves root certificate and signed certificate to a file
    pub fn save_signed_certificate_and_rootchain<P: AsRef<Path>>(&self, url: Option<&str>, dst_ca_path: P, path: P) -> Result<()> {
        let mut file = File::create(path)?;
        self.write_signed_certificate(&mut file)?;
        self.write_intermediate_certificate(url, &mut file)?;
        self.write_dst_root_ca_x3(dst_ca_path, &mut file)?;
        Ok(())
    }

    /// Saves private key used to sign certificate to a file
    pub fn write_dst_root_ca_x3<W: Write, P: AsRef<Path>>(&self, path: P, writer: &mut W) -> Result<()> {
        let cert = self.read_dst_root_ca_x3(path)?;
        writer.write_all(&cert.to_pem()?)?;
        Ok(())
    }

    /// Reads PKey from Path.
    fn read_dst_root_ca_x3<P: AsRef<Path>>(&self, path: P) -> Result<X509> {
        let mut file = File::open(path)?;
        let mut content = Vec::new();
        file.read_to_end(&mut content)?;
        Ok(X509::from_pem(&content)?)
    }

    /// Saves private key used to sign certificate to a file
    pub fn save_private_key<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut file = File::create(path)?;
        self.write_private_key(&mut file)
    }

    /// Saves CSR used to sign certificateto to a file
    pub fn save_csr<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut file = File::create(path)?;
        self.write_csr(&mut file)
    }

    /// Writes signed certificate to writer.
    pub fn write_signed_certificate<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.cert.to_pem()?)?;
        Ok(())
    }

    /// Writes intermediate certificate to writer.
    ///
    /// You can additionally provide intermediate certificate url, by default it will use
    /// [`LETS_ENCRYPT_INTERMEDIATE_CERT_URL`](constant.LETS_ENCRYPT_INTERMEDIATE_CERT_URL.html).
    pub fn write_intermediate_certificate<W: Write>(&self, url: Option<&str>, writer: &mut W) -> Result<()> {
        let cert = self.get_intermediate_certificate(url)?;
        writer.write_all(&cert.to_pem()?)?;
        Ok(())
    }

    /// Gets intermediate certificate from url.
    ///
    /// [`LETS_ENCRYPT_INTERMEDIATE_CERT_URL`](constant.LETS_ENCRYPT_INTERMEDIATE_CERT_URL.html).
    /// will be used if url is None.
    fn get_intermediate_certificate(&self, url: Option<&str>) -> Result<X509> {
        let client = Client::new();
        let mut res = client
            .get(url.unwrap_or(LETS_ENCRYPT_INTERMEDIATE_CERT_URL))
            .send()?;
        let mut content = Vec::new();
        res.read_to_end(&mut content)?;
        Ok(X509::from_pem(&content)?)
    }

    /// Writes private key used to sign certificate to a writer
    pub fn write_private_key<W: Write>(&self, writer: &mut W) -> Result<()> {
        Ok(writer.write_all(&self.pkey().private_key_to_pem_pkcs8()?)?)
    }

    /// Writes CSR used to sign certificateto a writer
    pub fn write_csr<W: Write>(&self, writer: &mut W) -> Result<()> {
        Ok(writer.write_all(&self.csr().to_pem()?)?)
    }

    /// Returns reference to certificate
    pub fn cert(&self) -> &X509 {
        &self.cert
    }

    /// Returns reference to CSR used to sign certificate
    pub fn csr(&self) -> &X509Req {
        &self.csr
    }

    /// Returns reference to pkey used to sign certificate
    pub fn pkey(&self) -> &PKey<openssl::pkey::Private> {
        &self.pkey
    }
}


impl<'a> Authorization<'a> {
    /// Gets a challenge.
    ///
    /// Pattern is used in `starts_with` for type comparison.
    pub fn get_challenge(&self, pattern: &str) -> Option<&Challenge> {
        for challenge in &self.0 {
            if challenge.ctype().starts_with(pattern) {
                return Some(challenge);
            }
        }
        None
    }

    /// Gets http challenge
    pub fn get_http_challenge(&self) -> Option<&Challenge> {
        self.get_challenge("http")
    }

    /// Gets dns challenge
    pub fn get_dns_challenge(&self) -> Option<&Challenge> {
        self.get_challenge("dns")
    }

    /// Gets tls-sni challenge
    pub fn get_tls_sni_challenge(&self) -> Option<&Challenge> {
        self.get_challenge("tls-sni")
    }

//    /// Gets all dns challenge
//    pub fn get_dns_challenges(&self) -> Option<&Vec<Challenge>> {
//        Some(&self.0)
//    }
}


impl<'a> Challenge<'a> {
    /// Saves key authorization into `{path}/.well-known/acme-challenge/{token}` for http challenge.
    pub fn save_key_authorization<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        use std::fs::create_dir_all;
        let path = path.as_ref().join(".well-known").join("acme-challenge");
        info!("Saving validation token into: {:?}", &path);
        create_dir_all(&path)?;

        let mut file = File::create(path.join(&self.token))?;
        writeln!(&mut file, "{}", self.key_authorization)?;

        Ok(())
    }

    /// Gets DNS validation signature.
    ///
    /// This value is used for verification of domain over DNS. Signature must be saved
    /// as a TXT record for `_acme_challenge.example.com`.
    pub fn signature(&self) -> Result<String> {
        Ok(b64(&hash(MessageDigest::sha256(),
                     &self.key_authorization.clone().into_bytes())?))
    }

    /// Returns challenge type, usually `http-01` or `dns-01` for Let's Encrypt.
    pub fn ctype(&self) -> &str {
        &self.ctype
    }

    /// Returns challenge token
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Returns key_authorization
    pub fn key_authorization(&self) -> &str {
        &self.key_authorization
    }

    /// Triggers validation.
    pub fn validate(&self) -> Result<()> {
        info!("[挑战验证] -> Triggering {} validation", self.ctype);

        // 获取请求的url
        //let url = self.url_for(resource).ok_or(format!("URL for resource: {} not found", resource))?;

        // 获取挑战签名...
        let challenge_token = self.signature().unwrap();
        debug!("validate info: [challenge_token: {:?}]", challenge_token);

        let payload = {
            let map = {
                let mut map: HashMap<String, Value> = HashMap::new();
                //map.insert("type".to_owned(), to_value(&self.ctype)?);
                //map.insert("token".to_owned(), to_value(&self.token)?);
                //map.insert("resource".to_owned(), to_value("challenge")?);
                //map.insert("keyAuthorization".to_owned(), to_value(&self.key_authorization)?);
                map.insert("keyAuthorization".to_owned(), to_value(challenge_token)?);
                map
            };
            self.account.directory().jws(&self.url, self.account.pkey(), map, Some(self.account.account_url.clone()))?
        };

        debug!("[COAM][####################][+++][&self.url: {}]", &self.url);
        debug!("[COAM][####################][+++][payload: {}]", payload);

        // 添加 [application/jose+json] 请求头
        let mut headers = HeaderMap::new();
        //headers.set(ContentType::json());
        headers.insert(reqwest::header::CONTENT_TYPE, "application/jose+json".parse().unwrap());

        // 发起请求...
        let client = Client::new();
        //let mut resp = client.post(&self.url).body(&payload[..]).send()?;
        let mut resp = client
            .post(&self.url)
            .headers(headers)
            .body(payload)
            .send()?;

        let mut res_json: Value = {
            let mut res_content = String::new();
            resp.read_to_string(&mut res_content)?;
            from_str(&res_content)?
        };

        debug!("[COAM][####################][+++][res_json: {}]", res_json);
        debug!("[COAM][####################][+++][status: {}]", resp.status());

        if resp.status() != StatusCode::OK {
            debug!("[###][####################][---][res_json: {}]", res_json);
            debug!("[###][####################][---][status: {}]", resp.status());
            return Err(ErrorKind::AcmeServerError(res_json).into());
        }

        loop {
            let status = res_json
                .as_object()
                .and_then(|o| o.get("status"))
                .and_then(|s| s.as_str())
                .ok_or("Status not found")?
                .to_owned();

            debug!("[COAM][####################][LOOP][res_json: {}]", res_json);
            debug!("[COAM][####################][LOOP][status: {}]", status);

            if status == "pending" {
                debug!("Status is pending, trying again...");
                let mut resp = client.get(&self.url).send()?;
                res_json = {
                    let mut res_content = String::new();
                    resp.read_to_string(&mut res_content)?;
                    from_str(&res_content)?
                };

                debug!("[challenge validate resp][res_json: {}]", res_json);
            } else if status == "valid" {
                info!("[挑战验证成功] -> Status is valid, trying next...");
                return Ok(());
            } else if status == "invalid" {
                return Err(ErrorKind::AcmeServerError(res_json).into());
            }

            use std::thread::sleep;
            use std::time::Duration;
            sleep(Duration::from_secs(2));
        }
    }
}


// header! is making a public struct,
// our custom header is private and only used privately in this module
//mod hyperx {
//    // ReplayNonce header for hyper
//    header! { (ReplayNonce, "Replay-Nonce") => [String] }
//}