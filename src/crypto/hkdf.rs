use crate::error::{Result, SignalError};
use hkdf::Hkdf;
use sha2::Sha256;

pub fn derive_keys(
    input_key_material: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(salt, input_key_material);
    let mut okm = vec![0u8; length];

    hk.expand(info, &mut okm)
        .map_err(|_| SignalError::Crypto("HKDF expansion failed".to_string()))?;

    Ok(okm)
}

pub fn kdf_rk(root_key: &[u8; 32], dh_output: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
    let hk = Hkdf::<Sha256>::new(Some(root_key), dh_output);
    let mut output = [0u8; 64];

    hk.expand(b"signal_ratchet", &mut output)
        .map_err(|_| SignalError::Crypto("KDF_RK failed".to_string()))?;

    let mut new_root_key = [0u8; 32];
    let mut new_chain_key = [0u8; 32];

    new_root_key.copy_from_slice(&output[0..32]);
    new_chain_key.copy_from_slice(&output[32..64]);

    Ok((new_root_key, new_chain_key))
}

pub fn kdf_ck(chain_key: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(chain_key);
    hasher.update([0x01]);
    let message_key = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(chain_key);
    hasher.update([0x02]);
    let next_chain_key = hasher.finalize();

    let mut mk = [0u8; 32];
    let mut nck = [0u8; 32];

    mk.copy_from_slice(&message_key[..]);
    nck.copy_from_slice(&next_chain_key[..]);

    Ok((mk, nck))
}
