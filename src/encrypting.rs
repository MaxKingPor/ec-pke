#[cfg(feature = "alloc")]
use alloc::{borrow::Cow, vec};
use elliptic_curve::{
    CurveArithmetic, Error, Group, PrimeField, ProjectivePoint, PublicKey, Result, SecretKey,
    bigint::Random,
    group::Curve,
    ops::{MulByGenerator, Reduce},
    scalar::FromUintUnchecked,
    sec1::{ModulusSize, ToEncodedPoint},
};
use rand_core::CryptoRngCore;
#[cfg(feature = "sm3")]
use sm3::Sm3;

use super::{Cipher, kdf};
use digest::{Digest, FixedOutputReset, Output};

/// Encrypt messages using elliptic curve cryptography.
pub trait EcEncrypt<C>
where
    C: CurveArithmetic,
{
    /// Encrypt into [`Cipher`] using the default digest algorithm [`Sm3`].
    #[cfg(all(feature = "alloc", feature = "sm3"))]
    fn encrypt<'a>(&self, msg: &[u8]) -> Result<Cipher<'a, C, Sm3>> {
        use rand_core::OsRng;

        self.encrypt_rng::<_>(&mut OsRng, msg)
    }

    /// Encrypt into [`Cipher`] using the default digest algorithm [`Sm3`].
    /// Use a custom RNG.
    #[cfg(feature = "alloc")]
    fn encrypt_rng<'a, R: CryptoRngCore>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> Result<Cipher<'a, C, Sm3>> {
        self.encrypt_digest_rng::<_, Sm3>(rng, msg)
    }

    /// Encrypt into [`Cipher`] using the default digest algorithm [`Sm3`].
    /// `c2_out_buf` is the output of c2.   
    /// Use a custom RNG.
    fn encrypt_buf_rng<'a, R: CryptoRngCore>(
        &self,
        rng: &mut R,
        msg: &[u8],
        c2_out_buf: &'a mut [u8],
    ) -> Result<Cipher<'a, C, Sm3>> {
        self.encrypt_buf_digest_rng::<R, Sm3>(rng, msg, c2_out_buf)
    }

    /// Encrypt into [`Cipher`] using the specified digest algorithm.
    #[cfg(all(feature = "alloc", feature = "os_rng"))]
    fn encrypt_digest<'a, D: Digest + FixedOutputReset>(
        &self,
        msg: &[u8],
    ) -> Result<Cipher<'a, C, D>> {
        use rand_core::OsRng;
        self.encrypt_digest_rng::<_, D>(&mut OsRng, msg)
    }
    /// Encrypt into [`Cipher`] using the specified digest algorithm.   
    /// Use a custom RNG.
    #[cfg(feature = "alloc")]
    fn encrypt_digest_rng<'a, R: CryptoRngCore, D: Digest + FixedOutputReset>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> Result<Cipher<'a, C, D>> {
        let mut c1 = C::AffinePoint::default();
        let mut c2 = vec![0; msg.len()];
        let mut c3 = Output::<D>::default();
        self.encrypt_digest_rng_into::<R, D>(rng, msg, &mut c1, &mut c2, &mut c3)?;
        Ok(Cipher {
            c1,
            c2: c2.into(),
            c3,
        })
    }

    /// Encrypt into [`Cipher`] using the specified digest algorithm.
    /// `c2_out_buf` is the output of c2.
    /// Use a custom RNG.
    fn encrypt_buf_digest_rng<'a, R: CryptoRngCore, D: Digest + FixedOutputReset>(
        &self,
        rng: &mut R,
        msg: &[u8],
        c2_out_buf: &'a mut [u8],
    ) -> Result<Cipher<'a, C, D>> {
        let mut c1 = C::AffinePoint::default();
        let mut c3 = Output::<D>::default();
        let len = self.encrypt_digest_rng_into::<R, D>(rng, msg, &mut c1, c2_out_buf, &mut c3)?;
        let c2 = &c2_out_buf[..len];

        #[cfg(feature = "alloc")]
        let c2 = Cow::Borrowed(c2);

        Ok(Cipher { c1, c2, c3 })
    }

    /// Implementation of encryption.
    /// Encrypt into the specified buffer using the specified digest algorithm.
    fn encrypt_digest_rng_into<R: CryptoRngCore, D: Digest + FixedOutputReset>(
        &self,
        rng: &mut R,
        msg: &[u8],
        c1_out: &mut C::AffinePoint,
        c2_out: &mut [u8],
        c3_out: &mut Output<D>,
    ) -> Result<usize>;
}

impl<C> EcEncrypt<C> for PublicKey<C>
where
    C: CurveArithmetic,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: ToEncodedPoint<C>,
{
    fn encrypt_digest_rng_into<R: CryptoRngCore, D: Digest + FixedOutputReset>(
        &self,
        rng: &mut R,
        msg: &[u8],
        c1_out: &mut <C as CurveArithmetic>::AffinePoint,
        c2_out: &mut [u8],
        c3_out: &mut Output<D>,
    ) -> Result<usize> {
        encrypt_into::<C, R, D>(self.as_affine(), rng, msg, c1_out, c2_out, c3_out)
    }
}
impl<C> EcEncrypt<C> for SecretKey<C>
where
    C: CurveArithmetic,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: ToEncodedPoint<C>,
{
    fn encrypt_digest_rng_into<R: CryptoRngCore, D: Digest + FixedOutputReset>(
        &self,
        rng: &mut R,
        msg: &[u8],
        c1_out: &mut <C as CurveArithmetic>::AffinePoint,
        c2_out: &mut [u8],
        c3_out: &mut Output<D>,
    ) -> Result<usize> {
        encrypt_into::<C, R, D>(
            self.public_key().as_affine(),
            rng,
            msg,
            c1_out,
            c2_out,
            c3_out,
        )
    }
}

fn encrypt_into<C, R, D>(
    affine_point: &C::AffinePoint,
    rng: &mut R,
    msg: &[u8],
    c1_out: &mut C::AffinePoint,
    c2_out: &mut [u8],
    c3_out: &mut Output<D>,
) -> Result<usize>
where
    C: CurveArithmetic,
    R: CryptoRngCore,
    D: FixedOutputReset + Digest,
    C::AffinePoint: ToEncodedPoint<C>,
    C::FieldBytesSize: ModulusSize,
{
    if c2_out.len() < msg.len() {
        return Err(Error);
    }
    let c2_out = &mut c2_out[..msg.len()];

    let mut digest = D::new();
    let mut hpb: C::AffinePoint;
    loop {
        // A1: generate a random number 𝑘 ∈ [1, 𝑛 − 1] with the random number generator
        let k: C::Scalar = C::Scalar::from_uint_unchecked(next_k::<_, C>(rng)?);

        // A2: compute point 𝐶1 = [𝑘]𝐺 = (𝑥1, 𝑦1)
        let kg: C::AffinePoint = ProjectivePoint::<C>::mul_by_generator(&k).into();

        // A3: compute point 𝑆 = [ℎ]𝑃𝐵 of the elliptic curve
        let scalar: C::Scalar = Reduce::<C::Uint>::reduce(C::Uint::from(C::Scalar::S.into()));
        let s: C::ProjectivePoint = C::ProjectivePoint::from(*affine_point) * scalar;
        if s.is_identity().into() {
            return Err(Error);
        }

        // A4: compute point [𝑘]𝑃𝐵 = (𝑥2, 𝑦2)
        hpb = (s * k).to_affine();

        // A5: compute 𝑡 = 𝐾𝐷𝐹(𝑥2||𝑦2, 𝑘𝑙𝑒𝑛)
        // A6: compute 𝐶2 = 𝑀 ⊕ t
        kdf::<D, C>(&mut digest, hpb, msg, c2_out)?;

        // // If 𝑡 is an all-zero bit string, go to A1.
        // if all of t are 0, xor(c2) == c2
        if c2_out.iter().zip(msg).any(|(pre, cur)| pre != cur) {
            *c1_out = kg;
            break;
        }
    }
    let encode_point = hpb.to_encoded_point(false);

    // A7: compute 𝐶3 = 𝐻𝑎𝑠ℎ(𝑥2||𝑀||𝑦2)
    Digest::reset(&mut digest);
    Digest::update(&mut digest, encode_point.x().ok_or(Error)?);
    Digest::update(&mut digest, msg);
    Digest::update(&mut digest, encode_point.y().ok_or(Error)?);
    Digest::finalize_into_reset(&mut digest, c3_out);

    Ok(c2_out.len())
}

fn next_k<R: CryptoRngCore, C>(rng: &mut R) -> Result<C::Uint>
where
    C: CurveArithmetic,
{
    Ok(C::Uint::random(rng))
}

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {
    use super::*;

    extern crate std;

    #[test]
    fn test_aa() {
        let key = sm2::SecretKey::random(&mut rand_core::OsRng);
        let a = key.encrypt("你好".as_bytes()).unwrap();
        let r = a.to_vec_compressed(crate::Mode::C1C3C2);
        std::println!("{r:?}");
    }
}
