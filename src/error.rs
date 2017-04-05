// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use hyper;
use openssl;
use rustc_serialize::base64::FromBase64Error;
use std::string::FromUtf8Error;

quick_error! {
    #[derive(Debug)]
    pub enum WebPushError {
        Openssl(e: openssl::error::ErrorStack) {
            from()
        }
        Hyper(e: hyper::error::Error) {
            from()
        }
        FromBase64(e: FromBase64Error) {
            from()
        }
        FromUtf8(e: FromUtf8Error) {
            from()
        }
        MissingGcmApiKey {}
        MalformedEncryptedData {}
    }
}

pub type WebPushResult<T> = Result<T, WebPushError>;

