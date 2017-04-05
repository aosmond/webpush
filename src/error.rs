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

pub type WebPushResult<T> = Result<T, WebPushError>; 

macro_rules! try_base64 {
    [ $maybe:expr ] => {
        match $maybe {
            Ok(value) => value,
            Err(e) => return Err(WebPushError::FromBase64(e)),
        }
    }
}

macro_rules! try_openssl {
    [ $maybe:expr ] => {
        match $maybe {
            Ok(value) => value,
            Err(e) => return Err(WebPushError::Openssl(e)),
        }
    }
}

macro_rules! try_hyper {
    [ $maybe:expr ] => {
        match $maybe {
            Ok(value) => value,
            Err(e) => return Err(WebPushError::Hyper(e)),
        }
    }
}

macro_rules! try_utf8 {
    [ $maybe:expr ] => {
        match $maybe {
            Ok(value) => value,
            Err(e) => return Err(WebPushError::FromUtf8(e)),
        }
    }
}

