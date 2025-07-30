use crate::error::{Result, SignalError};
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
use sha2::{Digest, Sha512};

pub fn sign(private_key: &[u8; 32], message: &[u8]) -> Result<[u8; 64]> {
    let scalar = Scalar::from_bytes_mod_order(*private_key);
    let public_point = scalar * ED25519_BASEPOINT_POINT;

    let mut hasher = Sha512::new();
    hasher.update(b"SignalXEdDSASign");
    hasher.update(private_key);
    hasher.update(message);
    let random_bytes = {
        let mut bytes = [0u8; 64];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        bytes
    };
    hasher.update(random_bytes);
    let r_bytes = hasher.finalize();
    let r = Scalar::from_bytes_mod_order(
        r_bytes[0..32]
            .try_into()
            .map_err(|_| SignalError::Crypto("Failed to create scalar".to_string()))?,
    );

    let R = r * ED25519_BASEPOINT_POINT;

    let mut hasher = Sha512::new();
    hasher.update(R.compress().as_bytes());
    hasher.update(public_point.compress().as_bytes());
    hasher.update(message);
    let h_bytes = hasher.finalize();
    let h = Scalar::from_bytes_mod_order(
        h_bytes[0..32]
            .try_into()
            .map_err(|_| SignalError::Crypto("Failed to create hash scalar".to_string()))?,
    );

    let s = r + (h * scalar);

    let mut signature = [0u8; 64];
    signature[0..32].copy_from_slice(R.compress().as_bytes());
    signature[32..64].copy_from_slice(s.as_bytes());

    Ok(signature)
}

pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<bool> {
    let public_scalar = Scalar::from_bytes_mod_order(*public_key);
    let public_point = public_scalar * ED25519_BASEPOINT_POINT;

    let R_bytes: [u8; 32] = signature[0..32]
        .try_into()
        .map_err(|_| SignalError::InvalidSignature)?;
    let s_bytes: [u8; 32] = signature[32..64]
        .try_into()
        .map_err(|_| SignalError::InvalidSignature)?;

    let R = curve25519_dalek::edwards::CompressedEdwardsY(R_bytes)
        .decompress()
        .ok_or(SignalError::InvalidSignature)?;
    let s = Scalar::from_bytes_mod_order(s_bytes);

    let mut hasher = Sha512::new();
    hasher.update(R.compress().as_bytes());
    hasher.update(public_point.compress().as_bytes());
    hasher.update(message);
    let h_bytes = hasher.finalize();
    let h = Scalar::from_bytes_mod_order(
        h_bytes[0..32]
            .try_into()
            .map_err(|_| SignalError::Crypto("Failed to create hash scalar".to_string()))?,
    );

    let lhs = s * ED25519_BASEPOINT_POINT;
    let rhs = R + (h * public_point);

    Ok(lhs == rhs)
}
