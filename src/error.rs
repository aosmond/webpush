// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use hyper;
use openssl;
use rustc_serialize::base64::FromBase64Error;
use std::string::FromUtf8Error;

#[derive(Debug)]
pub enum WebPushError {
    Openssl(openssl::error::ErrorStack),
    Hyper(hyper::error::Error),
    FromBase64(FromBase64Error),
    FromUtf8(FromUtf8Error),
    MissingGcmApiKey,
    MalformedEncryptedData,
}

impl From<openssl::error::ErrorStack> for WebPushError {
    fn from(err: openssl::error::ErrorStack) -> WebPushError {
        WebPushError::Openssl(err)
    }
}

impl From<hyper::error::Error> for WebPushError {
    fn from(err: hyper::error::Error) -> WebPushError {
        WebPushError::Hyper(err)
    }
}

impl From<FromBase64Error> for WebPushError {
    fn from(err: FromBase64Error) -> WebPushError {
        WebPushError::FromBase64(err)
    }
}

impl From<FromUtf8Error> for WebPushError {
    fn from(err: FromUtf8Error) -> WebPushError {
        WebPushError::FromUtf8(err)
    }
}

pub type WebPushResult<T> = Result<T, WebPushError>;

