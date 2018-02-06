#![deny(//missing_docs,
       missing_debug_implementations, missing_copy_implementations,
       trivial_casts, trivial_numeric_casts,
       unsafe_code,
       unstable_features,
       unused_import_braces, unused_qualifications)]
#![allow(dead_code)]

//! Contains functions and structs for sending and receiving SNMP messages.
extern crate byteorder;
pub mod types;
pub mod traits;
pub mod snmpv1;
