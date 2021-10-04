use rand::{CryptoRng, Rng};
use crate::LocalIdentity;

#[allow(dead_code)]
/// Prepare a MobileCoin public address to be sent to Signal's web API so that we can set the payment address field on an account's profile.
fn build_pay_address<R: CryptoRng + Rng>(mobilecoin_public_address: &[u8], our_identity: &LocalIdentity, csprng: &mut R) -> crate::Result<auxin_protos::PaymentAddress> { 
    let signature = our_identity.identity_keys.private_key().calculate_signature(mobilecoin_public_address, csprng)?;

    // Sgnature is supposed to be 64 bytes in length 
    assert_eq!(signature.len(), 64);
    let mut mobilecoin_addr = auxin_protos::PaymentAddress_MobileCoinAddress::default();
    mobilecoin_addr.set_signature(signature.to_vec());
    mobilecoin_addr.set_address(mobilecoin_public_address.to_vec());
    let mut pay_addr = auxin_protos::PaymentAddress::default();

    pay_addr.set_mobileCoinAddress(mobilecoin_addr);
    Ok(pay_addr)
}