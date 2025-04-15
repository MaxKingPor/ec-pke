//! SM2 Encryption Algorithm (SM2) as defined in [draft-shen-sm2-ecdsa § 5].
//!
//! ## Usage
#![cfg_attr(feature = "alloc", doc = "```")]
#![cfg_attr(not(feature = "alloc"), doc = "```ignore")]
//! use ec_pke::{EcDecrypt, EcEncrypt, Cipher, Mode};
//! use sm2::SecretKey;
//! use rand_core::OsRng;
//! // Encrypting
//! let secret_key = SecretKey::random(&mut OsRng);
//! let public_key = secret_key.public_key();
//! let plaintext = b"plaintext";
//! let cipher = public_key.encrypt(plaintext).unwrap();
//! let ciphertext = cipher.to_vec(Mode::C1C3C2);
//!
//! // Decrypting
//! let cipher = Cipher::from_slice(&ciphertext, Mode::C1C3C2).unwrap();
//! let ciphertext = secret_key.decrypt(&cipher).unwrap();
//! assert_eq!(ciphertext, plaintext)
//!  ```

#![no_std]

#[cfg(feature = "alloc")]
#[allow(unused_extern_crates)]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::{borrow::Cow, vec::Vec};
use core::cmp::min;
use der::{
    Decode, DecodeValue, Encode, EncodeValue, Length, Reader, Sequence, Writer,
    asn1::{OctetStringRef, UintRef},
};
use digest::{FixedOutputReset, Output, OutputSizeUser, Update, typenum::Unsigned};
use elliptic_curve::{
    AffinePoint, CurveArithmetic, Error, Group, PrimeField, Result,
    ops::Reduce,
    sec1::{FromEncodedPoint, ToEncodedPoint},
};

use sec1::{
    EncodedPoint,
    point::{ModulusSize, Tag},
};

pub mod decrypting;
pub mod encrypting;

pub use {self::decrypting::EcDecrypt, self::encrypting::EcEncrypt};
/// Modes for the cipher encoding/decoding.
#[derive(Clone, Copy, Debug)]
pub enum Mode {
    /// old mode
    C1C2C3,
    /// new mode
    C1C3C2,
}

/// Represents a cipher structure containing encryption-related data (asn.1 format).
///
/// The `Cipher` structure includes the coordinates of the elliptic curve point (`x`, `y`),
/// the digest of the message, and the encrypted cipher text.
#[derive(Debug)]
pub struct Cipher<'a, C: CurveArithmetic, D: OutputSizeUser> {
    c1: C::AffinePoint,
    #[cfg(feature = "alloc")]
    c2: Cow<'a, [u8]>,
    #[cfg(not(feature = "alloc"))]
    c2: &'a [u8],
    c3: Output<D>,
}

impl<'a, C, D> Cipher<'a, C, D>
where
    C: CurveArithmetic,
    C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
    C::FieldBytesSize: ModulusSize,
    D: OutputSizeUser,
{
    /// Decode from slice
    pub fn from_slice(cipher: &'a [u8], mode: Mode) -> Result<Self> {
        let tag = Tag::from_u8(cipher.first().cloned().ok_or(Error)?)?;
        let c1_len = tag.message_len(C::FieldBytesSize::USIZE);

        // B1: get 𝐶1 from 𝐶
        let (c1, c) = cipher.split_at(c1_len);
        // verify that point c1 satisfies the elliptic curve
        let encoded_c1 = EncodedPoint::from_bytes(c1)?;
        let c1: C::AffinePoint =
            Option::from(FromEncodedPoint::from_encoded_point(&encoded_c1)).ok_or(Error)?;
        // B2: compute point 𝑆 = [ℎ]𝐶1
        let scalar: C::Scalar = Reduce::<C::Uint>::reduce(C::Uint::from(C::Scalar::S.into()));

        let s: C::ProjectivePoint = C::ProjectivePoint::from(c1) * scalar;
        if s.is_identity().into() {
            return Err(Error);
        }

        let digest_size = D::output_size();
        let (c2, c3_buf) = match mode {
            Mode::C1C3C2 => {
                let (c3, c2) = c.split_at(digest_size);
                (c2, c3)
            }
            Mode::C1C2C3 => c.split_at(c.len() - digest_size),
        };

        let mut c3 = Output::<D>::default();
        c3.clone_from_slice(c3_buf);

        #[cfg(feature = "alloc")]
        let c2 = Cow::Borrowed(c2);

        Ok(Self { c1, c2, c3 })
    }

    /// Encode to Vec
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self, mode: Mode) -> Vec<u8> {
        let point = self.c1.to_encoded_point(false);
        let len = point.len() + self.c2.len() + self.c3.len();
        let mut result = Vec::with_capacity(len);
        match mode {
            Mode::C1C2C3 => {
                result.extend(point.as_ref());
                result.extend(self.c2.as_ref());
                result.extend(&self.c3);
            }
            Mode::C1C3C2 => {
                result.extend(point.as_ref());
                result.extend(&self.c3);
                result.extend(self.c2.as_ref());
            }
        }

        result
    }
    /// Encode to Vec
    #[cfg(feature = "alloc")]
    pub fn to_vec_compressed(&self, mode: Mode) -> Vec<u8> {
        let point = self.c1.to_encoded_point(true);
        let len = point.len() + self.c2.len() + self.c3.len();
        let mut result = Vec::with_capacity(len);
        match mode {
            Mode::C1C2C3 => {
                result.extend(point.as_ref());
                result.extend(self.c2.as_ref());
                result.extend(&self.c3);
            }
            Mode::C1C3C2 => {
                result.extend(point.as_ref());
                result.extend(&self.c3);
                result.extend(self.c2.as_ref());
            }
        }

        result
    }
    /// Get C1
    pub fn c1(&self) -> &C::AffinePoint {
        &self.c1
    }
    /// Get C2
    pub fn c2(&self) -> &[u8] {
        #[cfg(feature = "alloc")]
        return &self.c2;
        #[cfg(not(feature = "alloc"))]
        return self.c2;
    }
    /// Get C3
    pub fn c3(&self) -> &Output<D> {
        &self.c3
    }
}

impl<'a, C, D> Sequence<'a> for Cipher<'a, C, D>
where
    C: CurveArithmetic,
    D: OutputSizeUser,
    C::AffinePoint: ToEncodedPoint<C> + FromEncodedPoint<C>,
    C::FieldBytesSize: ModulusSize,
{
}

#[cfg_attr(feature = "alloc", allow(clippy::useless_asref))]
impl<C, D> EncodeValue for Cipher<'_, C, D>
where
    C: CurveArithmetic,
    D: OutputSizeUser,
    C::AffinePoint: ToEncodedPoint<C>,
    C::FieldBytesSize: ModulusSize,
{
    fn value_len(&self) -> der::Result<Length> {
        let point = self.c1.to_encoded_point(false);
        UintRef::new(point.x().unwrap())?.encoded_len()?
            + UintRef::new(point.y().unwrap())?.encoded_len()?
            + OctetStringRef::new(&self.c3)?.encoded_len()?
            + OctetStringRef::new(self.c2.as_ref())?.encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        let point = self.c1.to_encoded_point(false);
        UintRef::new(point.x().unwrap())?.encode(writer)?;
        UintRef::new(point.y().unwrap())?.encode(writer)?;
        OctetStringRef::new(&self.c3)?.encode(writer)?;
        OctetStringRef::new(self.c2.as_ref())?.encode(writer)?;
        Ok(())
    }
}

impl<'a, C, D> DecodeValue<'a> for Cipher<'a, C, D>
where
    C: CurveArithmetic,
    D: OutputSizeUser,
    C::AffinePoint: FromEncodedPoint<C>,
    C::FieldBytesSize: ModulusSize,
{
    fn decode_value<R: Reader<'a>>(
        decoder: &mut R,
        header: der::Header,
    ) -> core::result::Result<Self, der::Error> {
        decoder.read_nested(header.length, |nr| {
            let x = UintRef::decode(nr)?.as_bytes();
            let y = UintRef::decode(nr)?.as_bytes();
            let digest = OctetStringRef::decode(nr)?.as_bytes();
            let cipher = OctetStringRef::decode(nr)?.as_bytes();
            let size = C::FieldBytesSize::USIZE;
            if x.len() != size || y.len() != size {
                return Err(der::Error::new(
                    der::ErrorKind::Length {
                        tag: der::Tag::Integer,
                    },
                    der::Length::new(C::FieldBytesSize::U16),
                ));
            }
            let point = EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
            let c1 = Option::from(C::AffinePoint::from_encoded_point(&point)).ok_or_else(|| {
                der::Error::new(
                    der::ErrorKind::Value {
                        tag: der::Tag::Integer,
                    },
                    der::Length::ZERO,
                )
            })?;

            #[cfg(feature = "alloc")]
            let c2 = Cow::Borrowed(cipher);
            #[cfg(not(feature = "alloc"))]
            let c2 = cipher;

            let c3 = Output::<D>::clone_from_slice(digest);
            Ok(Cipher { c1, c2, c3 })
        })
    }
}

/// Performs key derivation using a hash function and elliptic curve point.     
/// Magic modification: Does it support streaming encryption and decryption?
fn kdf<D, C>(hasher: &mut D, kpb: AffinePoint<C>, msg: &[u8], c2_out: &mut [u8]) -> Result<()>
where
    D: Update + FixedOutputReset,
    C: CurveArithmetic,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: ToEncodedPoint<C>,
{
    let klen = msg.len();
    let mut ct: i32 = 0x00000001;
    let mut offset = 0;
    let digest_size = D::output_size();
    let mut ha = Output::<D>::default();
    let encode_point = kpb.to_encoded_point(false);

    hasher.reset();
    while offset < klen {
        hasher.update(encode_point.x().ok_or(Error)?);
        hasher.update(encode_point.y().ok_or(Error)?);
        hasher.update(&ct.to_be_bytes());

        hasher.finalize_into_reset(&mut ha);

        let xor_len = min(digest_size, klen - offset);
        xor(msg, c2_out, &ha, offset, xor_len);
        offset += xor_len;
        ct += 1;
    }
    Ok(())
}

/// XORs a portion of the buffer `c2` with a hash value.
fn xor(msg: &[u8], c2_out: &mut [u8], ha: &[u8], offset: usize, xor_len: usize) {
    for i in 0..xor_len {
        c2_out[offset + i] = msg[offset + i] ^ ha[i];
    }
}
