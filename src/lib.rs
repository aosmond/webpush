extern crate libc;
#[macro_use]
extern crate log;
extern crate openssl_sys;
extern crate rand;
extern crate rustc_serialize;

pub mod crypto;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
