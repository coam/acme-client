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
//! use acme_client::libs::v2::AcmeAuthDirectory;
//!
//! let directory = AcmeAuthDirectory::lets_encrypt()?;
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
//! use acme_client::libs::v2::AcmeAuthDirectory;
//!
//! let auth_directory = AcmeAuthDirectory::lets_encrypt()?;
//! let account = auth_directory.account_registration().register()?;
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
//! use acme_client::libs::v2::AcmeAuthDirectory;
//!
//! let auth_directory = AcmeAuthDirectory::lets_encrypt()?;
//! let account = auth_directory.account_registration()
//!                        .email("example@example.org")
//!                        .register()?;
//! # Ok(()) }
//! # fn main () { try_main().unwrap(); }
//! ```
//!
//! Contact email address is optional. You can also use your own private key during
//! registration. See [AcmeAccountRegistration](struct.AcmeAccountRegistration.html) helper for more
//! details.
//!
//! If you already registed with your own keys before, you still need to use
//! [`register`](struct.AcmeAccountRegistration.html#method.register) method,
//! in this case it will identify your user account instead of creating a new one.
//!
//!
//! ## Identifying ownership of domain name
//!
//! Before sending a certificate signing request to an ACME server, you need to identify ownership
//! of domain names you want to sign a certificate for. To do that you need to create an
//! AcmeAccountOrderAuthChallengeList object for a domain name and fulfill at least one challenge (http or dns for
//! Let's Encrypt).
//!
//! To create an AcmeAccountOrderAuthChallengeList object for a domain:
//!
//! ```rust,no_run
//! # use acme_client::libs::error::Result;
//! # fn try_main() -> Result<()> {
//! use acme_client::libs::v2::AcmeAuthDirectory;
//! # let auth_directory = AcmeAuthDirectory::lets_encrypt().unwrap();
//! # // Use staging auth_directory for doc test
//! # let auth_directory = AcmeAuthDirectory::from_url("https://acme-staging.api.letsencrypt.org/directory")
//! #   .unwrap();
//! # let account = auth_directory.account_registration().register().unwrap();
//! let authorization = account.authorization("example.com")?;
//! # Ok(()) }
//! # fn main () { try_main().unwrap(); }
//! ```
//!
//! [AcmeAccountOrderAuthChallengeList](struct.AcmeAccountOrderAuthChallengeList.html) object will contain challenges created by
//! ACME server. You can create as many AcmeAccountOrderAuthChallengeList object as you want to verify ownership
//! of the domain names. For example if you want to sign a certificate for
//! `example.com` and `example.org`:
//!
//! ```rust,no_run
//! # use acme_client::libs::error::Result;
//! # fn try_main() -> Result<()> {
//! use acme_client::libs::v2::AcmeAuthDirectory;
//! # let auth_directory = AcmeAuthDirectory::lets_encrypt().unwrap();
//! # let account = auth_directory.account_registration().register().unwrap();
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
//! [`save_key_authorization`](struct.AcmeAccountOrderAuthChallenge.html#method.save_key_authorization) method
//! to save vaditation file to a public auth_directory. This auth_directory must be accessible to outside
//! world.
//!
//! ```rust,no_run
//! # use acme_client::libs::error::Result;
//! # fn try_main() -> Result<()> {
//! use acme_client::libs::v2::AcmeAuthDirectory;
//! # let auth_directory = AcmeAuthDirectory::lets_encrypt()?;
//! # let account = auth_directory.account_registration()
//! #                        .pkey_from_file("tests/data/user.key")?  // use test key for doc test
//! #                        .register()?;
//! let authorization = account.authorization("example.com")?;
//! let http_challenge = authorization.get_http_challenge().ok_or("HTTP challenge not found")?;
//!
//! // This method will save key authorization into
//! // /var/www/.well-known/acme-challenge/ auth_directory.
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
//! [`signature`](struct.AcmeAccountOrderAuthChallenge.html#method.signature) method.
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
//! use acme_client::libs::v2::AcmeAuthDirectory;
//! # let auth_directory = AcmeAuthDirectory::lets_encrypt()?;
//! # let account = auth_directory.account_registration()
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
//! provides [`AcmeCertificateSigner`](struct.AcmeCertificateSigner.html) helper for this. You can
//! use your own key and CSR or you can let `AcmeCertificateSigner` to generate them for you.
//!
//! ```rust,no_run
//! # use acme_client::libs::error::Result;
//! # fn try_main() -> Result<()> {
//! use acme_client::libs::v2::AcmeAuthDirectory;
//! # let auth_directory = AcmeAuthDirectory::lets_encrypt()?;
//! # let account = auth_directory.account_registration().register()?;
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
//! use acme_client::libs::v2::AcmeAuthDirectory;
//! # let auth_directory = AcmeAuthDirectory::lets_encrypt()?;
//! let account = auth_directory.account_registration()
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

// openssl
use openssl::sign::Signer;
use openssl::hash::{hash, MessageDigest};
use openssl::pkey::PKey;
use openssl::x509::{X509, X509Req};

// reqwest
use reqwest::{Client, StatusCode};
use reqwest::header::HeaderMap;

// serde
use serde_json::{Value, from_str, to_string, to_value};
use serde::Serialize;

// dependence
use libs::helper::{gen_key, b64, read_private_key, gen_csr};
use libs::error::{Result, ErrorKind};

/// Default Let's Encrypt auth_directory URL to configure client.
pub const LETS_ENCRYPT_DIRECTORY_URL: &'static str = "https://acme-v02.api.letsencrypt.org/directory";
/// Default Let's Encrypt agreement URL used in account registration.
pub const LETS_ENCRYPT_AGREEMENT_URL: &'static str = "https://letsencrypt.org/documents/LE-SA-v2.2-November-15-2017.pdf";
/// Default Let's Encrypt intermediate certificate URL to chain when needed.
pub const LETS_ENCRYPT_INTERMEDIATE_CERT_URL: &'static str = "https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem";

/// Default bit lenght for RSA keys and `X509_REQ`
//const BIT_LENGTH: u32 = 2048;

/// AcmeAuthDirectory object to configure client. Main entry point of `acme-client`.
///
/// See [section-6.1.1](https://tools.ietf.org/html/draft-ietf-acme-acme-05#section-6.1.1)
/// for more details.
pub struct AcmeAuthDirectory {
    /// Base URL of directory
    acme_api: String,
    auth_directory: Value,
}

/// Registered account object.
///
/// Every operation requires a registered account. To register an `Account` you can use
/// `AcmeAuthDirectory::register_account` method.
///
/// See [AcmeAccountRegistration](struct.AcmeAccountRegistration.html) helper for more details.
pub struct AcmeAccountData {
    auth_directory: AcmeAuthDirectory,
    account_url: String,
    private_key: PKey<openssl::pkey::Private>,
}

/// Helper to register an account.
pub struct AcmeAccountRegistration {
    auth_directory: AcmeAuthDirectory,
    private_key: Option<PKey<openssl::pkey::Private>>,
    email: Option<String>,
    contact: Option<Vec<String>>,
    agreement: Option<String>,
}

/// Helper to sign a certificate.
pub struct AcmeCertificateSigner<'a> {
    account: &'a AcmeAccountData,
    domains: &'a [&'a str],
    private_key: Option<PKey<openssl::pkey::Private>>,
    csr: Option<X509Req>,
}

/// A signed certificate.
pub struct AcmeSignedCertificate {
    cert: X509,
    csr: X509Req,
    private_key: PKey<openssl::pkey::Private>,
}

impl AcmeAuthDirectory {
    /// Creates a AcmeAuthDirectory from
    /// [`LETS_ENCRYPT_DIRECTORY_URL`](constant.LETS_ENCRYPT_DIRECTORY_URL.html).
    pub fn lets_encrypt() -> Result<AcmeAuthDirectory> {
        AcmeAuthDirectory::from_url(LETS_ENCRYPT_DIRECTORY_URL)
    }

    /// Creates a AcmeAuthDirectory from directory URL.
    ///
    /// Example directory for testing `acme-client` crate with staging API:
    ///
    /// ```rust
    /// # use acme_client::libs::error::Result;
    /// # fn try_main() -> Result<()> {
    /// use acme_client::libs::v2::AcmeAuthDirectory;
    /// let dir = AcmeAuthDirectory::from_url("https://acme-staging.api.letsencrypt.org/directory")?;
    /// # Ok(()) }
    /// # fn main () { try_main().unwrap(); }
    /// ```
    pub fn from_url(url: &str) -> Result<AcmeAuthDirectory> {
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
        Ok(AcmeAuthDirectory {
            acme_api: url.to_owned(),
            auth_directory: from_str(&content)?,
        })
    }

    /// Returns url for the resource.
    pub fn url_for(&self, resource: &str) -> Option<&str> {
        self.auth_directory.as_object()
            .and_then(|o| o.get(resource))
            .and_then(|k| k.as_str())
    }

    /// Consumes directory and creates new AcmeAccountRegistration.
    ///
    /// AcmeAccountRegistration is used to register an account.
    ///
    /// ```rust,no_run
    /// # use acme_client::libs::error::Result;
    /// # fn try_main() -> Result<()> {
    /// use acme_client::libs::v2::AcmeAuthDirectory;
    ///
    /// let directory = AcmeAuthDirectory::lets_encrypt()?;
    /// let account = directory.account_registration()
    ///                        .email("example@example.org")
    ///                        .register()?;
    /// # Ok(()) }
    /// # fn main () { try_main().unwrap(); }
    /// ```
    pub fn account_registration(self) -> AcmeAccountRegistration {
        AcmeAccountRegistration {
            auth_directory: self,
            private_key: None,
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
        let acme_api = self.url_for("newNonce").unwrap_or(&self.acme_api);
        let client = Client::new();
        let res = client.get(acme_api).send()?;

        // 请求临时接口凭证
        res.headers().get("Replay-Nonce").ok_or("Replay-Nonce header not found".into())
            .and_then(|nonce| nonce.to_str().map_err(|_| "Nonce header value contains invalid characters".into()))
            .map(|nonce| nonce.to_string())
    }

    /// Makes a new post request to directory, signs payload with private_key.
    ///
    /// Returns status code and Value object from reply.
    fn request<T: Serialize>(&self, private_key: &PKey<openssl::pkey::Private>, resource: &str, payload: T, kid: Option<String>) -> Result<(StatusCode, Value, HeaderMap)> {
        let mut json = to_value(&payload)?;

        //let resource_json: Value = to_value(resource)?;
        //json.as_object_mut().and_then(|obj| obj.insert("resource".to_owned(), resource_json));

        trace!("[发起请求->request()][resource: {:?}][json: {:?}]", resource, json);

        // 获取请求的url
        let url = self.url_for(resource).ok_or(format!("URL for resource: {} not found", resource))?;

        // 获取 jws
        let jws = self.jws(url, private_key, json, kid)?;

        trace!("[发起请求->request()][url: {:?}][jws: {:?}]", url, jws);

        // 添加 [application/jose+json] 请求头
        let mut headers = HeaderMap::new();
        //headers.set(ContentType::json());
        headers.insert(reqwest::header::CONTENT_TYPE, "application/jose+json".parse().unwrap());

        // 请求客户端...
        let client = Client::new();
        let mut res = client.post(url)
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
    pub fn jws<T: Serialize>(&self, url: &str, private_key: &PKey<openssl::pkey::Private>, payload: T, kid: Option<String>) -> Result<String> {
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
            header.insert("jwk".to_owned(), self.jwk(private_key)?);
        }
        //data.insert("header".to_owned(), to_value(&header)?);

        let mut json = to_value(&payload)?;
        trace!("[发起请求->request()->jws()][payload: {:?}]", json);
        trace!("[发起请求->request()->jws()][protected=>header: {:?}]", header);

        // payload: b64 of payload
        let payload = to_string(&payload)?;
        let payload64 = b64(&payload.into_bytes());
        data.insert("payload".to_owned(), to_value(&payload64)?);

        // protected: base64 of header + nonce
        let protected64 = b64(&to_string(&header)?.into_bytes());
        data.insert("protected".to_owned(), to_value(&protected64)?);

        // signature: b64 of hash of signature of {proctected64}.{payload64}
        data.insert("signature".to_owned(), {
            let mut signer = Signer::new(MessageDigest::sha256(), &private_key)?;
            signer.update(&format!("{}.{}", protected64, payload64).into_bytes())?;
            to_value(b64(&signer.sign_to_vec()?))?
        });

        trace!("[发起请求->request()->jws()][data: {:?}]", data);

        let json_str = to_string(&data)?;
        Ok(json_str)
    }

    /// Returns jwk field of jws header
    pub fn jwk(&self, private_key: &PKey<openssl::pkey::Private>) -> Result<Value> {
        let rsa = private_key.rsa()?;
        let mut jwk: HashMap<String, String> = HashMap::new();
        jwk.insert("e".to_owned(), b64(&rsa.e().to_vec()));
        jwk.insert("kty".to_owned(), "RSA".to_owned());
        jwk.insert("n".to_owned(), b64(&rsa.n().to_vec()));
        Ok(to_value(jwk)?)
    }
}

// 账户授权响应数据...
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccountAuthResponse {
    status: String,
    expires: String,
    pub identifier: AcmeOrderDataIdentifier,
    // 授权挑战方案列表
    pub challenges: Vec<AcmeAccountAuthorizationChallenge>,
}

// 账户授权数据...
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccountAuthData {
    // 订单身份凭证
    pub auth_domain_identifier: AcmeOrderDataIdentifier,
    // DNS-01 授权验证挑战
    pub auth_dns_challenge: AcmeAccountAuthorizationChallenge,
}

// AcmeAccountOrderAuthChallenge 挑战...
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AcmeAccountAuthorizationChallenge {
    //r#type: String,
    #[serde(rename = "type")]
    pub types: String,
    pub status: String,
    pub url: String,
    pub token: String,
    pub wildcard: Option<bool>,
    #[serde(rename = "validationRecord")]
    pub validation_record: Option<Vec<AcmeAccountAuthorizationChallengeValidationRecord>>,
    // 授权签名...
    pub key_authorization: Option<String>,
    pub auth_challenge_token: Option<String>,
}

// AcmeAccountOrderAuthChallenge 挑战...
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AcmeAccountAuthorizationChallengeValidationRecord {
    hostname: String,
}

impl AcmeAccountData {
    /// load a signed certificate from pem formatted file
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

    /// Creates a new `AcmeCertificateSigner` helper to sign a certificate for list of domains.
    ///
    /// `domains` must be list of the domain names you want to sign a certificate for.
    /// Currently there is no way to retrieve subject alt names from a X509Req.
    ///
    /// You can additionally use your own private key and CSR.
    /// See [`AcmeCertificateSigner`](struct.AcmeCertificateSigner.html) for details.
    pub fn certificate_signer<'a>(&'a self, domains: &'a [&'a str]) -> AcmeCertificateSigner<'a> {
        AcmeCertificateSigner {
            account: self,
            domains: domains,
            private_key: None,
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

            self.directory().request(self.private_key(), "revoke-cert", map, None)?
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
        Ok(writer.write_all(&self.private_key().private_key_to_pem_pkcs8()?)?)
    }

    /// Saves account private key to a file
    pub fn save_private_key<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut file = File::create(path)?;
        self.write_private_key(&mut file)
    }

    /// Returns a reference to account private key
    pub fn private_key(&self) -> &PKey<openssl::pkey::Private> {
        &self.private_key
    }

    /// Returns a reference to directory used to create account
    pub fn directory(&self) -> &AcmeAuthDirectory {
        &self.auth_directory
    }

    // 创建订单构造器...
    pub fn order_creator(&self) -> OrderCreator {
        OrderCreator {
            order_identifiers: None,
        }
    }
}

impl AcmeAccountRegistration {
    /// Sets contact email address
    pub fn email(mut self, email: &str) -> AcmeAccountRegistration {
        self.email = Some(email.to_owned());
        self
    }

    /// Sets contact details such as telephone number (Let's Encrypt only supports email address).
    pub fn contact(mut self, contact: &[&str]) -> AcmeAccountRegistration {
        self.contact = Some(contact.iter().map(|c| c.to_string()).collect());
        self
    }

    /// Sets agreement url,
    /// [`LETS_ENCRYPT_AGREEMENT_URL`](constant.LETS_ENCRYPT_AGREEMENT_URL.html)
    /// will be used during registration if it's not set.
    pub fn agreement(mut self, url: &str) -> AcmeAccountRegistration {
        self.agreement = Some(url.to_owned());
        self
    }

    /// Sets account private key. A new key will be generated if it's not set.
    pub fn private_key(mut self, private_key: PKey<openssl::pkey::Private>) -> AcmeAccountRegistration {
        self.private_key = Some(private_key);
        self
    }

    /// Sets PKey from a PEM formatted file.
    pub fn private_key_from_file<P: AsRef<Path>>(mut self, path: P) -> Result<AcmeAccountRegistration> {
        self.private_key = Some(read_private_key(path)?);
        Ok(self)
    }

    /// Registers an account.
    ///
    /// A PKey will be generated if it doesn't exists.
    pub fn register(self) -> Result<AcmeAccountData> {
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

        let private_key = self.private_key.unwrap_or(gen_key()?);

        let (status, resp, resp_headers) = self.auth_directory.request(&private_key, "newAccount", map, None)?;

        debug!("[请求账户注册结果][status: {:?}][resp: {:?}][resp_headers: {:?}]", status, resp, resp_headers);

        match status {
            StatusCode::OK => info!("[账户注册成功] -> StatusCode::OK - User successfully registered!"),
            StatusCode::CREATED => info!("[账户注册成功] -> StatusCode::CREATED - User successfully registered!"),
            StatusCode::CONFLICT => info!("[账户注册成功] -> StatusCode::CONFLICT - User already registered!"),
            _ => return Err(ErrorKind::AcmeServerError(resp).into()),
        };

        // 账户地址...
        let account_url = resp_headers.get("location").unwrap();

        Ok(AcmeAccountData {
            auth_directory: self.auth_directory,
            account_url: String::from(account_url.to_str().unwrap()),
            private_key: private_key,
        })
    }
}

/// Helper to create an order.
//#[derive(Serialize, Deserialize, Debug)]
pub struct OrderCreator {
    order_identifiers: Option<Vec<AcmeOrderDataIdentifier>>,
}

// 订单数据
#[derive(Serialize, Deserialize, Debug)]
pub struct AcmeOrderData {
    //auth_directory: AcmeAuthDirectory,
    pub account_url: String,
    pub order_url: String,
    pub finalize_url: String,
    pub certificate: Option<String>,
    //private_key: PKey<openssl::pkey::Private>,
    pub authorizations: Vec<String>,
    pub identifiers: Vec<AcmeOrderDataIdentifier>,
    // 获取订单授权挑战
    pub auth_list: Vec<AccountAuthResponse>,
}

impl AcmeOrderData {
    /// Creates a new identifier authorization object for domain
    pub fn request_acme_order_auth_list(&mut self) -> Result<&AcmeOrderData> {
        info!("[循环验证 ACME 订单] -> Sending authorization request for order: {:?}", self);

        // 循环授权验证...
        for authorization in &self.authorizations {
            println!("\n");
            info!("[开始发起 ACME 订单验证挑战] -> For send authorization request for [authorization: {:?}]", authorization);

            // 发起授权验证...
            let client = Client::new();
            //let mut resp = client.get(authorization).send()?;
            let mut auth_resp = client.get(authorization).send()?;

            // [How do you make a GET request in Rust?](https://stackoverflow.com/questions/43222429/how-do-you-make-a-get-request-in-rust)
            // copy the response body directly to stdout
            //std::io::copy(&mut auth_resp, &mut std::io::stdout())?;

            trace!("[####################][+++][status: {:?}]", auth_resp.status());
            trace!("[####################][+++]Headers:\n{:?}", auth_resp.headers());
            trace!("[####################][+++]auth_resp: \n{:?}", auth_resp);

            // 获取授权数据...
            let mut account_auth_response: AccountAuthResponse = auth_resp.json()?;
            info!("[账户订单验证挑战][+++]auth_resp.account_auth_response: \n{:?}", account_auth_response);

            // 依次读取授权数据
            let auth_domain_identifier = account_auth_response.identifier.clone();
            let account_auth_challenges = account_auth_response.challenges.clone();
            debug!("[####]循环验证TXT解析数据: auth_domain_identifier: {:?}", auth_domain_identifier);
            debug!("[####]循环验证TXT解析数据: account_auth_challenges: {:?}", account_auth_challenges);

            // 过滤查询 dns-01 挑战...
            let dns_challenge = account_auth_challenges.iter().find(|challenge| challenge.types == "dns-01");
            if let Some(challenge) = dns_challenge {
                info!("[已匹配挑战: dns-01] in challenges: {:?}", challenge);
            } else {
                panic!("[未匹配挑战: dns-01] -- Find none [dns-01] in challenges");
            }

            // 获取 [DNS-01] 授权挑战...
            let mut auth_dns_challenge = dns_challenge.unwrap().clone();

            // 获取挑战...
            let token = auth_dns_challenge.token.clone();
            let types = auth_dns_challenge.types.clone();
            let url = auth_dns_challenge.url.clone();

            // 授权挑战数据...
            //let account_auth_data = AccountAuthData { auth_domain_identifier, auth_dns_challenge };

            // 推入授权列表...
            self.auth_list.push(account_auth_response);
        }

        Ok(self)
    }

    /// Creates a new identifier authorization object for domain
    pub fn get_acme_order_auth_list(&self, acme_account: &AcmeAccountData) -> Result<Vec<AccountAuthData>> {
        info!("[循环验证 ACME 订单] -> Sending authorization request for order: {:?}", self);

        // 授权列表...
        let mut acme_order_auth_list = Vec::<AccountAuthData>::new();

        // 循环授权挑战验证列表...
        for account_auth_response in &self.auth_list {
            println!("\n");
            info!("[开始发起 ACME 订单验证挑战] -> For send authorization request for [account_auth_response: {:?}]", account_auth_response);

            // 依次读取授权数据
            let auth_domain_identifier = account_auth_response.identifier.clone();
            let account_auth_challenges = account_auth_response.challenges.clone();
            debug!("[####]循环验证TXT解析数据: auth_domain_identifier: {:?}", auth_domain_identifier);
            debug!("[####]循环验证TXT解析数据: account_auth_challenges: {:?}", account_auth_challenges);

            // 过滤查询 dns-01 挑战...
            let dns_challenge = account_auth_challenges.iter().find(|challenge| challenge.types == "dns-01");
            if let Some(challenge) = dns_challenge {
                info!("[已匹配挑战: dns-01] in challenges: {:?}", challenge);
            } else {
                panic!("[未匹配挑战: dns-01] -- Find none [dns-01] in challenges");
            }

            // 获取 [DNS-01] 授权挑战...
            let mut auth_dns_challenge = dns_challenge.unwrap().clone();

            // 获取挑战...
            let token = auth_dns_challenge.token.clone();
            let types = auth_dns_challenge.types.clone();
            let url = auth_dns_challenge.url.clone();

            // This seems really cryptic but it's not
            // https://tools.ietf.org/html/draft-ietf-acme-acme-05#section-7.1
            // key-authz = token || '.' || base64url(JWK\_Thumbprint(accountKey))
            let key_thumbprint = b64(&hash(MessageDigest::sha256(), &to_string(&acme_account.directory().jwk(acme_account.private_key())?)?.into_bytes())?);
            let key_authorization = format!("{}.{}", auth_dns_challenge.token, key_thumbprint);
            //let challenge_token = b64(&hash(MessageDigest::sha256(), key_authorization.as_bytes())?);

            // 获取挑战签名...
            let challenge = AcmeAccountOrderAuthChallenge {
                account: acme_account,
                ctype: types,
                url: url,
                token: token,
                key_authorization: key_authorization.clone(),
            };
            let auth_challenge_token = challenge.signature().unwrap();
            info!("[域名挑战验证签名 `dns-01` TXT解析值] authorization challenge info: [auth_challenge_token: {:?}][key_thumbprint: {:?}][key_authorization: {:?}]", auth_challenge_token, key_thumbprint, key_authorization);

            // 保存授权...
            auth_dns_challenge.key_authorization = Some(key_authorization);
            auth_dns_challenge.auth_challenge_token = Some(auth_challenge_token);

            // 授权挑战数据...
            let account_auth_data = AccountAuthData { auth_domain_identifier, auth_dns_challenge };

            // 推入授权列表...
            acme_order_auth_list.push(account_auth_data);
        }

        Ok(acme_order_auth_list)
    }
}

// 订单接口数据
#[derive(Serialize, Deserialize, Debug)]
pub struct AcmeOrderResponse {
    pub status: String,
    pub finalize: String,
    pub certificate: Option<String>,
    pub expires: String,
    pub authorizations: Vec<String>,
    pub identifiers: Vec<AcmeOrderDataIdentifier>,
}

// DNS 解析记录
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AcmeOrderDataIdentifier {
    #[serde(rename = "type")]
    pub types: String,
    pub value: String,
}

impl OrderCreator {
    /// Sets contact email address
    pub fn identifiers(mut self, order_identifiers: Vec<AcmeOrderDataIdentifier>) -> OrderCreator {
        self.order_identifiers = Some(order_identifiers);
        self
    }

    /// Registers an account.
    ///
    /// A PKey will be generated if it doesn't exists.
    pub fn create(self, account: &AcmeAccountData) -> Result<AcmeOrderData> {
        info!("[执行创建订单流程]Creating order");

        let mut map = HashMap::new();

        // 创建订单域名...
        map.insert("identifiers".to_owned(), &self.order_identifiers);

        info!("[发起创建订单请求参数][resources: createOrder][map: {:?}]", map);

        let private_key = &account.private_key;
        let account_url = &account.account_url;

        let (status, resp, resp_headers) = account.directory().request(&private_key, "newOrder", map, Some(account_url.clone()))?;

        debug!("[创建订单请求结果][status: {:?}][resp: {:?}][resp_headers: {:?}]", status, resp, resp_headers);

        match status {
            StatusCode::OK => info!("[订单创建成功] -> Order successfully ok"),
            StatusCode::CREATED => info!("[订单创建成功] -> Order successfully created"),
            _ => return Err(ErrorKind::AcmeServerError(resp).into()),
        };

        // 解析结构体数据...
        let order_response: AcmeOrderResponse = serde_json::from_str(&resp.to_string())?;

        // 账户地址...
        let order_url = resp_headers.get("location").unwrap().to_str().unwrap();

        Ok(AcmeOrderData {
            account_url: account_url.clone(),
            order_url: order_url.to_string(),
            finalize_url: order_response.finalize,
            certificate: None,
            authorizations: order_response.authorizations,
            identifiers: order_response.identifiers,
            auth_list: Vec::<AccountAuthResponse>::new(),
        })
    }
}

impl<'a> AcmeCertificateSigner<'a> {
    /// Set PKey of CSR
    pub fn private_key(mut self, private_key: PKey<openssl::pkey::Private>) -> AcmeCertificateSigner<'a> {
        self.private_key = Some(private_key);
        self
    }

    /// Load PEM formatted PKey from file
    pub fn private_key_from_file<P: AsRef<Path>>(mut self, path: P) -> Result<AcmeCertificateSigner<'a>> {
        self.private_key = Some(read_private_key(path)?);
        Ok(self)
    }

    /// Set CSR to sign
    pub fn csr(mut self, csr: X509Req) -> AcmeCertificateSigner<'a> {
        self.csr = Some(csr);
        self
    }

    /// Load PKey and CSR from file
    pub fn csr_from_file<P: AsRef<Path>>(mut self, private_key_path: P, csr_path: P) -> Result<AcmeCertificateSigner<'a>> {
        self.private_key = Some(read_private_key(private_key_path)?);
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
    pub fn create_certificate(mut self) -> Result<AcmeCertificateSigner<'a>> {
        // 创建证书...
        let private_key = self.private_key.unwrap_or(gen_key().unwrap());
        let csr = self.csr.unwrap_or(gen_csr(&private_key, self.domains).unwrap());

        // 创建证书...
        self.private_key = Some(private_key);
        self.csr = Some(csr);

        Ok(self)
    }

    /// finalize_order.
    /// CSR and PKey will be generated if it doesn't set or loaded first.
    pub fn finalize_order<'b, 'c>(&'b self, order: &'c mut AcmeOrderData) -> Result<&'c AcmeOrderData> {
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
            self.account.directory().jws(finalize_url, self.account.private_key(), map.clone(), Some(self.account.account_url.clone()))?
        };

        debug!("[COAM][####################][+++][finalize_url: {}]", finalize_url);
        debug!("[COAM][####################][+++][payload: {}]", payload);

        // 添加 [application/jose+json] 请求头
        let mut headers = HeaderMap::new();
        //headers.set(ContentType::json());
        headers.insert(reqwest::header::CONTENT_TYPE, "application/jose+json".parse().unwrap());

        // 发起请求...
        let client = Client::new();
        //let jws = self.account.directory().jws(finalize_url, self.account.private_key(), map, Some(self.account.account_url.clone()))?
        let mut res = client.post(finalize_url)
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

        let mut order_response: AcmeOrderResponse = res.json()?;
        trace!("[####################][+++]res.order_response: \n{:?}", order_response);

        // 判断是否经过验证...
        if order_response.status != "valid" {
            panic!("未验证通过!");
        }

        // [How do you make a GET request in Rust?](https://stackoverflow.com/questions/43222429/how-do-you-make-a-get-request-in-rust)
        // copy the response body directly to stdout
        //std::io::copy(&mut res, &mut std::io::stdout())?;

        trace!("[####################][---][status: {:?}]", res.status());
        trace!("[####################][---]Headers:\n{:?}", res.headers());
        trace!("[####################][---]res: \n{:?}", res);

        // 复制证书...
        order.certificate = order_response.certificate;

        Ok(order)
    }

    /// Signs certificate.
    ///
    /// CSR and PKey will be generated if it doesn't set or loaded first.
    pub fn sign_certificate(self, order: &AcmeOrderData) -> Result<AcmeSignedCertificate> {
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

        trace!("[####################][---][status: {:?}]", res.status());
        trace!("[####################][---]Headers:\n{:?}", res.headers());
        trace!("[####################][---]res: \n{:?}", res);

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

        Ok(AcmeSignedCertificate {
            cert: cert,
            csr: self.csr.unwrap(),
            private_key: self.private_key.unwrap(),
        })
    }
}

impl AcmeSignedCertificate {
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
        Ok(writer.write_all(&self.private_key().private_key_to_pem_pkcs8()?)?)
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

    /// Returns reference to private_key used to sign certificate
    pub fn private_key(&self) -> &PKey<openssl::pkey::Private> {
        &self.private_key
    }
}

/// Identifier authorization object.
pub struct AcmeAccountOrderAuthChallengeList<'a>(pub Vec<AcmeAccountOrderAuthChallenge<'a>>);

/// A verification challenge.
pub struct AcmeAccountOrderAuthChallenge<'a> {
    pub account: &'a AcmeAccountData,
    /// Type of verification challenge. Usually `http-01`, `dns-01` for letsencrypt.
    pub ctype: String,
    /// URL to trigger challenge.
    pub url: String,
    /// AcmeAccountOrderAuthChallenge token.
    pub token: String,
    /// Key authorization.
    pub key_authorization: String,
}

impl<'a> AcmeAccountOrderAuthChallengeList<'a> {
    /// Gets a challenge.
    ///
    /// Pattern is used in `starts_with` for type comparison.
    pub fn get_challenge(&self, pattern: &str) -> Option<&AcmeAccountOrderAuthChallenge> {
        for challenge in &self.0 {
            if challenge.ctype().starts_with(pattern) {
                return Some(challenge);
            }
        }
        None
    }

    /// Gets http challenge
    pub fn get_http_challenge(&self) -> Option<&AcmeAccountOrderAuthChallenge> {
        self.get_challenge("http")
    }

    /// Gets dns challenge
    pub fn get_dns_challenge(&self) -> Option<&AcmeAccountOrderAuthChallenge> {
        self.get_challenge("dns")
    }

    /// Gets tls-sni challenge
    pub fn get_tls_sni_challenge(&self) -> Option<&AcmeAccountOrderAuthChallenge> {
        self.get_challenge("tls-sni")
    }

    /// Gets all dns challenge
    pub fn get_dns_challenges(&self) -> Option<&Vec<AcmeAccountOrderAuthChallenge>> {
        Some(&self.0)
    }
}

impl<'a> AcmeAccountOrderAuthChallenge<'a> {
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
        Ok(b64(&hash(MessageDigest::sha256(), &self.key_authorization.clone().into_bytes())?))
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
                map.insert("keyAuthorization".to_owned(), to_value(challenge_token)?);
                map
            };
            self.account.directory().jws(&self.url, self.account.private_key(), map, Some(self.account.account_url.clone()))?
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
        let mut resp = client.post(&self.url)
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
            error!("[###][####################][---][res_json: {}]", res_json);
            error!("[###][####################][---][status: {}]", resp.status());
            return Err(ErrorKind::AcmeServerError(res_json).into());
        }

        loop {
            // 验证挑战状态
            let status = res_json.as_object()
                .and_then(|o| o.get("status"))
                .and_then(|s| s.as_str())
                .ok_or("Status not found")?
                .to_owned();

            debug!("[COAM][####################][LOOP][res_json: {}]", res_json);
            debug!("[COAM][####################][LOOP][status: {}]", status);

            // 区分验证状态...
            if status == "pending" {
                info!("[循环挑战验证状态] -> [challenge validate status: pending], trying again...");

                // 请求结果
                let mut resp = client.get(&self.url).send()?;
                res_json = {
                    let mut res_content = String::new();
                    resp.read_to_string(&mut res_content)?;
                    from_str(&res_content)?
                };

                warn!("[challenge validate status: pending][res_json: {}]", res_json);
            } else if status == "valid" {
                info!("[循环挑战验证状态] -> [challenge validate status: valid], trying next...");
                return Ok(());
            } else if status == "invalid" {
                error!("[循环挑战验证状态] -> [challenge validate status: invalid], trying ended...");
                return Err(ErrorKind::AcmeServerError(res_json).into());
            }

            // 循环等待验证...
            use std::thread::sleep;
            use std::time::Duration;
            sleep(Duration::from_secs(2));
        }
    }
}