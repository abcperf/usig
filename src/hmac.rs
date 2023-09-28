use std::{collections::HashMap, fmt::Debug};

use crate::{Count, Counter, SignHalf, UsigError, VerifyHalf};

use super::Usig;

use serde::{Deserialize, Serialize};

use hmac::Mac;

use derivative::Derivative;

use generic_array::{ArrayLength, GenericArray};
use hmac::digest::{InvalidLength, KeyInit};
use shared_ids::ReplicaId;
use trait_alias_macro::pub_trait_alias_macro;

pub_trait_alias_macro!(MacType = Mac + Debug + KeyInit + Clone);

#[derive(Derivative, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
#[derivative(Debug(bound = ""))]
pub struct Signature<L: ArrayLength<u8>> {
    counter: u64,
    signature: GenericArray<u8, L>,
}

impl<L: ArrayLength<u8>> Counter for Signature<L> {
    fn counter(&self) -> Count {
        Count(self.counter)
    }
}

type Key = Box<[u8]>;

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct UsigHmacSignHalf<M: MacType> {
    counter: u64,
    hmac: M,
    key: Key,
}

impl<M: MacType> UsigHmacSignHalf<M> {
    pub fn try_new(key: Box<[u8]>) -> Result<Self, InvalidLength> {
        Ok(Self {
            counter: 0,
            hmac: Mac::new_from_slice(&key)?,
            key,
        })
    }
}

impl<M: MacType> SignHalf for UsigHmacSignHalf<M> {
    type Signature = Signature<M::OutputSize>;
    type Attestation = Key;

    fn sign(&mut self, message: impl AsRef<[u8]>) -> Result<Self::Signature, UsigError> {
        let counter = self.counter;
        self.counter += 1;

        let mut hmac = self.hmac.clone();

        Mac::update(&mut hmac, &counter.to_be_bytes());
        Mac::update(&mut hmac, message.as_ref());

        Ok(Signature {
            counter,
            signature: hmac.finalize().into_bytes(),
        })
    }

    fn attest(&mut self) -> Result<Self::Attestation, UsigError> {
        Ok(self.key.clone())
    }
}

#[derive(Derivative)]
#[derivative(Debug(bound = ""), Default(bound = ""))]
pub struct UsigHmacVerifyHalf<M: MacType> {
    other_hmacs: HashMap<ReplicaId, M>,
}

impl<M: MacType> VerifyHalf for UsigHmacVerifyHalf<M> {
    type Signature = Signature<M::OutputSize>;
    type Attestation = Key;

    fn verify(
        &self,
        id: ReplicaId,
        message: impl AsRef<[u8]>,
        signature: &Self::Signature,
    ) -> Result<(), UsigError> {
        if let Some(hmac) = self.other_hmacs.get(&id) {
            let Signature { counter, signature } = signature;
            let mut hmac = hmac.clone();

            Mac::update(&mut hmac, &counter.to_be_bytes());
            Mac::update(&mut hmac, message.as_ref());

            hmac.verify(signature)
                .map_err(|_| UsigError::InvalidSignature)
        } else {
            Err(UsigError::UnknownId(id))
        }
    }

    fn add_remote_party(&mut self, id: ReplicaId, attestation: Self::Attestation) -> bool {
        if let Ok(hmac) = Mac::new_from_slice(&attestation) {
            self.other_hmacs.insert(id, hmac);
            true
        } else {
            false
        }
    }
}

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct UsigHmac<M: MacType> {
    sign_half: UsigHmacSignHalf<M>,
    verify_half: UsigHmacVerifyHalf<M>,
}

impl<M: MacType> UsigHmac<M> {
    pub fn try_new(key: Box<[u8]>) -> Result<Self, InvalidLength> {
        Ok(Self {
            sign_half: UsigHmacSignHalf::try_new(key)?,
            verify_half: UsigHmacVerifyHalf::default(),
        })
    }
}

impl<M: MacType> Usig for UsigHmac<M> {
    type Signature = Signature<M::OutputSize>;
    type Attestation = Key;

    fn sign(&mut self, message: impl AsRef<[u8]>) -> Result<Self::Signature, UsigError> {
        self.sign_half.sign(message)
    }

    fn attest(&mut self) -> Result<Self::Attestation, UsigError> {
        self.sign_half.attest()
    }

    fn verify(
        &self,
        id: ReplicaId,
        message: impl AsRef<[u8]>,
        signature: &Self::Signature,
    ) -> Result<(), UsigError> {
        self.verify_half.verify(id, message, signature)
    }

    fn add_remote_party(&mut self, id: ReplicaId, attestation: Self::Attestation) -> bool {
        self.verify_half.add_remote_party(id, attestation)
    }

    type SignHalf = UsigHmacSignHalf<M>;
    type VerifyHalf = UsigHmacVerifyHalf<M>;

    fn split(self) -> (Self::SignHalf, Self::VerifyHalf) {
        (self.sign_half, self.verify_half)
    }
}

#[cfg(test)]
mod tests {
    use crate::tests;

    use crate as usig;

    use super::Key;
    use super::UsigHmac;

    use hmac::Hmac;
    use rand::{rngs::OsRng, RngCore};
    use sha2::Sha256;

    tests!({
        let mut key = [0u8; 16];
        OsRng.fill_bytes(&mut key);
        UsigHmac::<Hmac<Sha256>>::try_new(Key::from(key)).unwrap()
    });
}
