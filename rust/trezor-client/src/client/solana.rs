use super::{handle_interaction, Trezor, TrezorResponse};
use crate::{error::Result, protos, Error};

pub use crate::protos::{SolanaTxAdditionalInfo, SolanaTxTokenAccountInfo};

impl Trezor {
    // SOLANA
    pub fn solana_get_address(&mut self, path: Vec<u32>) -> Result<String> {
        handle_interaction(self.solana_get_address_with(path, true)?)
    }

    /// Get the Solana address at `path`, optionally displaying it on the device
    /// for verification. Interaction requests (e.g. a passphrase request) are
    /// returned to the caller.
    pub fn solana_get_address_with(
        &mut self,
        path: Vec<u32>,
        show_display: bool,
    ) -> Result<TrezorResponse<'_, String, protos::SolanaAddress>> {
        let mut req = protos::SolanaGetAddress::new();
        req.address_n = path;
        req.show_display = Some(show_display);
        self.call(req, Box::new(|_, m: protos::SolanaAddress| Ok(m.address().into())))
    }

    /// The Solana address at `path` with its SLIP-24 MAC (proof to the device
    /// that the address is its own, for payment requests). Not displayed.
    pub fn solana_get_address_mac(
        &mut self,
        path: Vec<u32>,
    ) -> Result<TrezorResponse<'_, (String, Vec<u8>), protos::SolanaAddress>> {
        let mut req = protos::SolanaGetAddress::new();
        req.address_n = path;
        req.show_display = Some(false);
        self.call(
            req,
            Box::new(|_, m: protos::SolanaAddress| Ok((m.address().into(), m.mac().to_vec()))),
        )
    }

    /// Get the raw 32-byte Solana (ed25519) public key at `path`.
    pub fn solana_get_public_key(
        &mut self,
        path: Vec<u32>,
        show_display: bool,
    ) -> Result<TrezorResponse<'_, [u8; 32], protos::SolanaPublicKey>> {
        let mut req = protos::SolanaGetPublicKey::new();
        req.address_n = path;
        req.show_display = Some(show_display);
        self.call(
            req,
            Box::new(|_, m: protos::SolanaPublicKey| {
                m.public_key().try_into().map_err(|_| Error::MalformedSignature)
            }),
        )
    }

    /// Sign a serialized Solana transaction message (the bytes after the
    /// signature section of a wire transaction) with the key at `path`.
    ///
    /// `additional_info` describes token accounts referenced by the transaction
    /// so the device can display SPL token transfers properly.
    pub fn solana_sign_tx(
        &mut self,
        path: Vec<u32>,
        serialized_tx: Vec<u8>,
        additional_info: Option<SolanaTxAdditionalInfo>,
    ) -> Result<TrezorResponse<'_, [u8; 64], protos::SolanaTxSignature>> {
        let mut req = protos::SolanaSignTx::new();
        if let Some(pr) = self.payment_request.take() {
            req.payment_req = protobuf::MessageField::some(pr);
        }
        req.address_n = path;
        req.set_serialized_tx(serialized_tx);
        if let Some(info) = additional_info {
            req.additional_info = protobuf::MessageField::some(info);
        }
        self.call(
            req,
            Box::new(|_, m: protos::SolanaTxSignature| {
                m.signature().try_into().map_err(|_| Error::MalformedSignature)
            }),
        )
    }
}
