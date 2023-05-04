//! Proof of knowledge of committed values in a vector Pedersen commitment––Commit and Prove scheme.
//!
//! `ProverCommitting` will contains vectors of generators and random values.
//! `ProverCommitting` has a `commit` method that optionally takes a value as blinding, if not provided, it creates its own.
//! `ProverCommitting` has a `finish` method that results in creation of `ProverCommitted` object after consuming `ProverCommitting`
//! `ProverCommitted` marks the end of commitment phase and has the final commitment.
//! `ProverCommitted` has a method to generate the challenge by hashing all generators and commitment. It is optional
//! to use this method as the challenge may come from a super-protocol or from verifier. It takes a vector of bytes that it includes for hashing for computing the challenge
//! `ProverCommitted` has a method `gen_proof` to generate proof. It takes the secrets and the challenge to generate responses.
//! During response generation `ProverCommitted` is consumed to create `Proof` object containing the commitments and responses.
//! `Proof` can then be verified by the verifier.

use crate::errors::{BBSError, BBSErrorKind};
use crate::{
    hash_to_fr, multi_scalar_mul_const_time_g1, rand_non_zero_fr, Commitment, GeneratorG1,
    ProofChallenge, SignatureMessage, ToVariableLengthBytes, FR_COMPRESSED_SIZE,
    G1_COMPRESSED_SIZE, G1_UNCOMPRESSED_SIZE,
};

use ff_zeroize::Field;
use pairing_plus::{
    bls12_381::{Fr, G1},
    serdes::SerDes,
    CurveAffine, CurveProjective,
};
use serde::{
    de::{Error as DError, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::convert::TryFrom;
use std::fmt::Formatter;
use std::io::{Cursor, Read};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// Convenience importing module
pub mod prelude {
    pub use super::{ProofG1, ProverCommittedG1, ProverCommittingG1};
}

/// Proof of knowledge of messages in a vector commitment.
/// Commit for each message or blinding factor used
#[derive(Clone, Debug)]
pub struct ProverCommittingG1 {
    bases: Vec<G1>,
    blinding_factors: Vec<Fr>,
}

/// Receive or generate challenge. Compute response and proof
#[derive(Clone, Debug)]
pub struct ProverCommittedG1 {
    /// The generators to use as the bases
    bases: Vec<G1>,
    /// The blinding factors as part of the proof
    blinding_factors: Vec<Fr>,
    /// The commitment to be verified as part of the proof
    commitment: G1,
}

/// A proof of knowledge of a signature and hidden messages
#[derive(Clone, Debug)]
pub struct ProofG1 {
    /// The proof commitment of all base_0*exp_0+base_1*exp_1
    pub(crate) commitment: G1,
    /// s values in the fiat shamir protocol
    pub(crate) responses: Vec<Fr>,
}

impl ProverCommittingG1 {
    /// Create a new prover committing struct
    pub fn new() -> Self {
        Self {
            bases: Vec::new(),
            blinding_factors: Vec::new(),
        }
    }

    /// Commit a base point with a blinding factor.
    /// The blinding factor is generated randomly
    pub fn commit<B: AsRef<G1>>(&mut self, base: B) -> usize {
        let idx = self.bases.len();
        self.bases.push(base.as_ref().clone());
        let r = rand_non_zero_fr();
        self.blinding_factors.push(r);
        idx
    }

    /// Commit a base point with a blinding factor.
    pub fn commit_with<B: AsRef<G1>, S: AsRef<Fr>>(
        &mut self,
        base: B,
        blinding_factor: S,
    ) -> usize {
        let idx = self.bases.len();
        self.bases.push(base.as_ref().clone());
        self.blinding_factors.push(blinding_factor.as_ref().clone());
        idx
    }

    /// Add pairwise product of (`self.bases`, self.blindings). Uses multi-exponentiation.
    pub fn finish(self) -> ProverCommittedG1 {
        let commitment = multi_scalar_mul_const_time_g1(&self.bases, &self.blinding_factors);
        ProverCommittedG1 {
            bases: self.bases,
            blinding_factors: self.blinding_factors,
            commitment,
        }
    }

    /// Return the generator and blinding factor at `idx`
    pub fn get_index(&self, idx: usize) -> Result<(GeneratorG1, SignatureMessage), BBSError> {
        if idx >= self.bases.len() {
            return Err(BBSErrorKind::GeneralError {
                msg: format!("index {} greater than size {}", idx, self.bases.len()),
            }
            .into());
        }
        Ok((
            GeneratorG1(self.bases[idx]),
            SignatureMessage(self.blinding_factors[idx]),
        ))
    }
}

impl Default for ProverCommittingG1 {
    fn default() -> Self {
        Self::new()
    }
}

impl ProverCommittedG1 {
    /// Convert the committed values to a byte array. Use for generating the fiat-shamir challenge
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for b in &self.bases {
            b.serialize(&mut bytes, false).unwrap();
        }
        self.commitment.serialize(&mut bytes, false).unwrap();
        bytes
    }

    /// This step will be done by the main protocol for which this PoK is a sub-protocol
    pub fn gen_challenge<I: AsRef<[u8]>>(&self, extra: I) -> ProofChallenge {
        let mut bytes = self.to_bytes();
        bytes.extend_from_slice(extra.as_ref());
        ProofChallenge(hash_to_fr(&bytes))
    }

    /// For each secret, generate a response as self.blinding[i] - challenge*secrets[i].
    pub fn gen_proof(
        self,
        challenge: &ProofChallenge,
        secrets: &[SignatureMessage],
    ) -> Result<ProofG1, BBSError> {
        check_matching_bases(secrets.len(), self.bases.len())?;
        let mut responses = Vec::with_capacity(self.bases.len());
        for i in 0..self.bases.len() {
            let mut c = challenge.0;
            c.mul_assign(&secrets[i].0);
            let mut s = self.blinding_factors[i];
            s.sub_assign(&c);
            responses.push(s);
        }
        Ok(ProofG1 {
            commitment: self.commitment,
            responses,
        })
    }
}

impl ProofG1 {
    /// Computes the piece that goes into verifying the overall proof component
    /// by computing the c == H(U || \widehat{U} || nonce)
    /// This returns the \widehat{U}
    /// commitment is U
    pub fn get_challenge_contribution(
        &self,
        bases: &[GeneratorG1],
        commitment: &Commitment,
        challenge: &ProofChallenge,
    ) -> Result<GeneratorG1, BBSError> {
        // bases[0]^responses[0] * bases[0]^responses[0] * ... bases[i]^responses[i] * commitment^challenge == random_commitment
        // =>
        // bases[0]^responses[0] * bases[0]^responses[0] * ... bases[i]^responses[i] * commitment^challenge * random_commitment^-1 == 1
        check_matching_bases(bases.len(), self.responses.len())?;
        let mut points: Vec<G1> = bases.iter().map(|g| g.0).collect();
        let mut scalars = self.responses.clone();
        points.push(commitment.0);
        scalars.push(challenge.0);
        Ok(GeneratorG1(multi_scalar_mul_const_time_g1(
            &points, &scalars,
        )))
    }

    /// Verify that bases[0]^responses[0] * bases[0]^responses[0] * ... bases[i]^responses[i] * commitment^challenge == random_commitment
    pub fn verify(
        &self,
        bases: &[GeneratorG1],
        commitment: &Commitment,
        challenge: &ProofChallenge,
    ) -> Result<bool, BBSError> {
        let mut pr = self.get_challenge_contribution(bases, commitment, challenge)?;
        pr.0.sub_assign(&self.commitment);
        Ok(pr.0.is_zero())
    }

    /// Assumes this is the entire proof and is not a sub proof
    /// Used primarily during 2-PC signature creation
    pub fn verify_complete_proof(
        &self,
        bases: &[GeneratorG1],
        commitment: &Commitment,
        challenge: &ProofChallenge,
        nonce: &[u8],
    ) -> Result<bool, BBSError> {
        check_matching_bases(bases.len(), self.responses.len())?;
        let mut points: Vec<G1> = bases.iter().map(|b| b.0).collect();
        let bases = points.clone();
        let mut scalars = self.responses.clone();
        points.push(commitment.0);
        scalars.push(challenge.0);
        let mut pr = multi_scalar_mul_const_time_g1(&points, &scalars);
        let mut pr_bytes = Vec::new();

        for b in bases {
            pr_bytes.extend_from_slice(b.into_affine().into_uncompressed().as_ref());
        }
        pr_bytes.extend_from_slice(pr.into_affine().into_uncompressed().as_ref());
        pr_bytes.extend_from_slice(commitment.0.into_affine().into_uncompressed().as_ref());
        pr_bytes.extend_from_slice(nonce);
        let mut hash = hash_to_fr(pr_bytes.as_slice());
        hash.sub_assign(&challenge.0);
        pr.sub_assign(&self.commitment);
        Ok(pr.is_zero() && hash.is_zero())
    }

    /// Convert to raw bytes
    pub(crate) fn to_bytes(&self, compressed: bool) -> Vec<u8> {
        let mut result = Vec::new();
        self.commitment.serialize(&mut result, compressed).unwrap();
        let len: u32 = self.responses.len() as u32;
        result.extend_from_slice(&len.to_be_bytes()[..]);

        for r in self.responses.iter() {
            r.serialize(&mut result, compressed).unwrap();
        }
        result
    }

    /// Convert from raw bytes
    pub(crate) fn from_bytes(
        data: &[u8],
        g_size: usize,
        compressed: bool,
    ) -> Result<Self, BBSError> {
        if data.len() < g_size + 4 {
            return Err(BBSErrorKind::SignaturePoKError {
                msg: "Invalid length".to_string(),
            }
            .into());
        }
        let mut c = Cursor::new(data);

        let commitment = slice_to_elem!(&mut c, G1, compressed)?;

        let mut length_bytes = [0u8; 4];
        c.read_exact(&mut length_bytes).unwrap();
        let length = u32::from_be_bytes(length_bytes) as usize;

        if data.len() < g_size + 4 + length * FR_COMPRESSED_SIZE {
            return Err(BBSErrorKind::SignaturePoKError {
                msg: "Invalid length".to_string(),
            }
            .into());
        }

        let mut responses = Vec::with_capacity(length);

        for _ in 0..length {
            let r = slice_to_elem!(&mut c, Fr, compressed)?;
            responses.push(r);
        }
        Ok(Self {
            commitment,
            responses,
        })
    }
}

impl Default for ProofG1 {
    fn default() -> Self {
        Self {
            commitment: G1::zero(),
            responses: Vec::new(),
        }
    }
}

impl ToVariableLengthBytes for ProofG1 {
    type Output = ProofG1;
    type Error = BBSError;

    fn to_bytes_compressed_form(&self) -> Vec<u8> {
        self.to_bytes(true)
    }

    fn from_bytes_compressed_form<I: AsRef<[u8]>>(data: I) -> Result<Self, BBSError> {
        Self::from_bytes(data.as_ref(), G1_COMPRESSED_SIZE, true)
    }

    fn to_bytes_uncompressed_form(&self) -> Vec<u8> {
        self.to_bytes(false)
    }

    fn from_bytes_uncompressed_form<I: AsRef<[u8]>>(data: I) -> Result<Self, BBSError> {
        Self::from_bytes(data.as_ref(), G1_UNCOMPRESSED_SIZE, false)
    }
}

try_from_impl!(ProofG1, BBSError);
serdes_impl!(ProofG1);

fn check_matching_bases(a: usize, b: usize) -> Result<(), BBSError> {
    if a != b {
        Err(BBSErrorKind::SignaturePoKError {
            msg: format!(
                "Same no of bases and exponents required. Provided {a} bases \
                and {b} exponents",
            ),
        }
        .into())
    } else {
        Ok(())
    }
}

#[cfg(feature = "wasm")]
wasm_slice_impl!(ProofG1);

#[cfg(test)]
macro_rules! test_PoK_VC {
    ( $n:ident, $ProverCommitting:ident, $ProverCommitted:ident, $Proof:ident, $group_element:ident, $group_element_size:ident ) => {
        let mut gens = Vec::with_capacity($n);
        let mut secrets = Vec::with_capacity($n);
        let mut commiting = $ProverCommitting::new();
        for _ in 0..$n - 1 {
            let g = $group_element::random();
            commiting.commit(&g);
            gens.push(g);
            secrets.push(SignatureMessage::random());
        }

        // Add one of the blindings externally
        let g = $group_element::random();
        let r = SignatureMessage::random();
        commiting.commit_with(&g, &r);
        let (g_, r_) = commiting.get_index($n - 1).unwrap();
        assert_eq!(g, g_);
        assert_eq!(r, r_);
        gens.push(g);
        secrets.push(SignatureMessage::random());

        // Bound check for get_index
        assert!(commiting.get_index($n).is_err());
        assert!(commiting.get_index($n + 1).is_err());

        let committed = commiting.finish();
        let gs: Vec<G1> = gens.iter().map(|g| g.0).collect();
        let ss: Vec<Fr> = secrets.iter().map(|s| s.0).collect();
        let commitment = Commitment(multi_scalar_mul_const_time_g1(&gs, &ss));
        let challenge = committed.gen_challenge(committed.to_bytes());
        let proof = committed.gen_proof(&challenge, secrets.as_slice()).unwrap();

        assert!(proof.verify(&gens, &commitment, &challenge).unwrap());

        let proof_bytes = proof.to_bytes_uncompressed_form();
        assert_eq!(
            proof_bytes.len(),
            $group_element_size + 4 + FR_COMPRESSED_SIZE * proof.responses.len()
        );
        let res_proof_cp = $Proof::from_bytes_uncompressed_form(&proof_bytes);
        assert!(res_proof_cp.is_ok());

        // Unequal number of generators and responses
        let mut gens_1 = gens.clone();
        let g1 = $group_element::random();
        gens_1.push(g1);
        // More generators
        assert!(proof
            .verify(gens_1.as_slice(), &commitment, &challenge)
            .is_err());

        let mut gens_2 = gens.clone();
        gens_2.pop();
        // Less generators
        assert!(proof
            .verify(gens_2.as_slice(), &commitment, &challenge)
            .is_err());

        // Wrong commitment fails to verify
        assert!(!proof
            .verify(
                gens.as_slice(),
                &Commitment(GeneratorG1::random().0),
                &challenge
            )
            .unwrap());
        // Wrong challenge fails to verify
        assert!(!proof
            .verify(gens.as_slice(), &commitment, &ProofChallenge::random())
            .unwrap());
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RandomElem;

    #[test]
    fn test_pok_vc_g1() {
        let n = 5;
        test_PoK_VC!(
            n,
            ProverCommittingG1,
            ProverCommittedG1,
            ProofG1,
            GeneratorG1,
            G1_UNCOMPRESSED_SIZE
        );
    }
}
