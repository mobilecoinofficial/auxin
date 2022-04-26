// Copyright (c) 2021 MobileCoin Inc.
// Copyright (c) 2021 Emily Cultip


// TODO: Post-refactor only UUID (as in ACI) will be used internally, and the type passed in as a potential address for a peer will be a different type.

/// Phone number (as formatted to the E.164 standard).
/// String should begin with '+', followed by a country code and a regular 10-digit phone number (no delimiters between parts, as in no "-" or " ").
pub type E164 = String;
// Possibly move to using https://github.com/rustonaut/rust-phonenumber when needed

/// Single-device Signal accounts are assumed to have a device ID of 1. Device ID 0 appears to be an error code or reserved.
pub const DEFAULT_DEVICE_ID: u32 = 1;