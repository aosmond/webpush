// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use crypto::CryptoContext;
use hyper;
use hyper::header::{ContentEncoding, Encoding, Authorization};
use hyper::Client;
use hyper::client::Body;
use hyper::client::response::Response;
use hyper::net::HttpsConnector;
use hyper_native_tls::NativeTlsClient;
use std::cmp::max;

header! { (Encryption, "Encryption") => [String] }
header! { (EncryptionKey, "Encryption-Key") => [String] }
header! { (CryptoKey, "Crypto-Key") => [String] }
header! { (Ttl, "TTL") => [u32] }

pub enum Error {
    MissingGcmApiKey,
    EncryptFailed,
    Hyper(hyper::error::Error),
}

pub struct SubscriptionManager
{
    gcm_api_key: Option<String>,
    crypto: CryptoContext,
}

impl SubscriptionManager {
    pub fn new(gcm_api_key: Option<String>) -> Self {
        SubscriptionManager {
            gcm_api_key: gcm_api_key,
            crypto: CryptoContext::new().unwrap(),
        }
    }

    pub fn with_crypto(crypto: CryptoContext, gcm_api_key: Option<String>) -> Self {
        SubscriptionManager {
            gcm_api_key: gcm_api_key,
            crypto: crypto,
        }
    }

    pub fn post(&self, sub: &Subscription, message: &str) -> Result<Response, Error> {
        let gcm_api_key = match self.gcm_api_key {
            Some(ref x) => &x,
            None => "",
        };
        sub.post(&self.crypto, gcm_api_key, message)
    }
}

pub struct Subscription {
    push_uri: String,
    public_key: String,
    auth: Option<String>
}

impl Subscription {
    pub fn new(push_uri: &str, public_key: &str, auth: &str) -> Self {
        Subscription {
            push_uri: push_uri.to_owned(),
            public_key: public_key.to_owned(),
            auth: Some(auth.to_owned()),
        }
    }

    pub fn post(&self, crypto: &CryptoContext, gcm_api_key: &str, message: &str) -> Result<Response, Error> {
        // Make the record size at least the size of the encrypted message. We must
        // add 16 bytes for the encryption tag, 1 byte for padding and 1 byte to
        // ensure we don't end on a record boundary.
        //
        // https://tools.ietf.org/html/draft-ietf-webpush-encryption-02#section-3.2
        //
        // "An application server MUST encrypt a push message with a single record.
        //  This allows for a minimal receiver implementation that handles a single
        //  record. If the message is 4096 octets or longer, the "rs" parameter MUST
        //  be set to a value that is longer than the encrypted push message length."
        //
        // The push service is not obligated to accept larger records however.
        //
        // "Note that a push service is not required to support more than 4096 octets
        // of payload body, which equates to 4080 octets of cleartext, so the "rs"
        // parameter can be omitted for messages that fit within this limit."
        //
        let record_size = max(4096, message.len() + 18);
        let enc = match crypto.encrypt(&self.public_key,
                                       message.to_owned(),
                                       &self.auth,
                                       record_size) {
            Some(x) => x,
            None => {
                warn!("notity subscription {} failed for {}",
                      self.push_uri,
                      message);
                return Err(Error::EncryptFailed);
            }
        };

        // If using Google's push service, we need to replace the given endpoint URI
        // with one known to work with WebPush, as support has not yet rolled out to
        // all of its servers.
        //
        // https://github.com/GoogleChrome/web-push-encryption/blob/dd8c58c62b1846c481ceb066c52da0d695c8415b/src/push.js#L69
        let push_uri = self.push_uri.replace("https://android.googleapis.com/gcm/send",
                                             "https://gcm-http.googleapis.com/gcm");

        let ssl = NativeTlsClient::new().unwrap();
        let connector = HttpsConnector::new(ssl);
        let client = Client::with_connector(connector);

        let has_auth = self.auth.is_some();
        let public_key = crypto.get_public_key(has_auth);
        let mut req = client.post(&push_uri)
            .header(Encryption(format!("keyid=p256dh;salt={};rs={}", enc.salt, record_size)))
            .body(Body::BufBody(&enc.output, enc.output.len()));

        // If using Google's push service, we need to provide an Authorization header
        // which provides an API key permitting us to send push notifications. This
        // should be provided in foxbox.conf as webpush/gcm_api_key in base64.
        //
        // https://github.com/GoogleChrome/web-push-encryption/blob/dd8c58c62b1846c481ceb066c52da0d695c8415b/src/push.js#L84
        if push_uri != self.push_uri {
            if gcm_api_key.is_empty() {
                warn!("cannot notify subscription {}, GCM API key missing from foxbox.conf",
                      push_uri);
                return Err(Error::MissingGcmApiKey);
            }
            req = req.header(Authorization(format!("key={}", gcm_api_key)));
        }

        req = if has_auth {
            req.header(ContentEncoding(vec![Encoding::EncodingExt(String::from("aesgcm"))]))
                .header(CryptoKey(format!("keyid=p256dh;dh={}", public_key)))

                // Set the TTL which controls how long the push service will wait before giving
                // up on delivery of the notification
                //
                // https://tools.ietf.org/html/draft-ietf-webpush-protocol-04#section-6.2
                //
                // "An application server MUST include the TTL (Time-To-Live) header
                //  field in its request for push message delivery.  The TTL header field
                //  contains a value in seconds that suggests how long a push message is
                //  retained by the push service.
                //
                //      TTL = 1*DIGIT
                //
                //  A push service MUST return a 400 (Bad Request) status code in
                //  response to requests that omit the TTL header field."
                //
                //  TODO: allow the notifier to control this; right now we default to 24 hours
                .header(Ttl(86400))
        } else {
            req.header(ContentEncoding(vec![Encoding::EncodingExt(String::from("aesgcm128"))]))
                .header(EncryptionKey(format!("keyid=p256dh;dh={}", public_key)))
        };

        // TODO: Add a retry mechanism if 429 Too Many Requests returned by push service
        let rsp = match req.send() {
            Ok(x) => x,
            Err(e) => {
                warn!("notify subscription {} failed: {:?}", push_uri, e);
                return Err(Error::Hyper(e));
            }
        };

        info!("notified subscription {} (status {:?})", push_uri, rsp.status);
        Ok(rsp)
    }
}
