//! Monero support: addresses, watch-only key export, key image sync and transaction signing.
//!
//! This module only speaks the Trezor wire protocol. It performs no Monero cryptography; the
//! caller (a Monero wallet) prepares the inputs (rings, real outputs, masks), and assembles and
//! verifies the final transaction from the parts returned here. Key images and CLSAG signatures
//! come back encrypted, together with the key to open them, exactly as the firmware sends them.
//!
//! Derivation path: `m/44'/128'/account'` (ed25519, all hardened).
//!
//! All methods acknowledge on-device confirmation prompts but never answer a passphrase
//! request; unlock the session (host-entered passphrase) before calling them.

use super::{InteractionType, Trezor, TrezorResponse};
use crate::{
    error::{Error, Result},
    protos::{
        self, monero_key_image_export_init_request::MoneroSubAddressIndicesList,
        monero_key_image_sync_step_ack::MoneroExportedKeyImage,
        monero_key_image_sync_step_request::MoneroTransferDetails,
        monero_transaction_init_request::MoneroTransactionData, MoneroNetworkType,
        MoneroTransactionDestinationEntry, MoneroTransactionSourceEntry,
    },
};
use protobuf::MessageField;

/// BIP-32 path `m/44'/128'/account'` used by Trezor for Monero accounts.
pub fn monero_path(account: u32) -> Vec<u32> {
    const H: u32 = 0x8000_0000;
    vec![44 | H, 128 | H, account | H]
}

/// Result of [`Trezor::monero_get_watch_key`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoneroWatchKey {
    /// The account's private view key (32 bytes, little-endian scalar).
    pub watch_key: Vec<u8>,
    /// The account's primary address.
    pub address: String,
}

/// Result of [`Trezor::monero_key_image_sync`].
#[derive(Debug, Clone, PartialEq)]
pub struct MoneroKeyImageSyncResult {
    /// One encrypted entry per transfer, in request order. Each `blob` is a
    /// ChaCha20-Poly1305 (IETF, 12-byte `iv`) ciphertext with a 16-byte tag; the plaintext is
    /// `key_image (32) || signature c (32) || signature r (32)`.
    pub key_images: Vec<MoneroExportedKeyImage>,
    /// Decryption key for `key_images`, released by the device after the final step.
    pub enc_key: Vec<u8>,
}

/// Input to [`Trezor::monero_sign_tx`].
#[derive(Debug, Clone)]
pub struct MoneroSignTxRequest {
    /// Account path, see [`monero_path`].
    pub address_n: Vec<u32>,
    /// Network.
    pub network_type: MoneroNetworkType,
    /// Transaction data. `num_inputs` is overwritten with `inputs.len()`. The firmware requires
    /// `client_version >= 3`, `hard_fork >= 13`, BP+ (`rsig_data.bp_version == 4`) and at least
    /// two outputs. With more than two outputs the firmware expects host-computed
    /// (offloaded) range proofs, which this driver does not support.
    pub tsx_data: MoneroTransactionData,
    /// Source entries in their original order. Each must list every ring member with both its
    /// global index (`idx`) and keys, sorted by global index.
    pub inputs: Vec<MoneroTransactionSourceEntry>,
}

/// Everything the host needs to assemble the signed transaction.
///
/// Inputs (`vins`, `pseudo_outs`, `signatures`) are in the final, key-image-sorted order;
/// `permutation[i]` is the original index of sorted input `i`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoneroSignedTxParts {
    /// Sorted index -> original input index.
    pub permutation: Vec<usize>,
    /// Serialized `txin_to_key` (variant tag 0x02 included) per input.
    pub vins: Vec<Vec<u8>>,
    /// Pseudo-output commitments per input (as finally used in the signatures).
    pub pseudo_outs: Vec<Vec<u8>>,
    /// Encrypted CLSAG per input (ciphertext || 16-byte tag), see `opening_key`.
    pub signatures: Vec<Vec<u8>>,
    /// Serialized `tx_out` per output.
    pub tx_outs: Vec<Vec<u8>>,
    /// `dest (32) || commitment (32)` per output.
    pub out_pks: Vec<Vec<u8>>,
    /// Encrypted 8-byte amount per output.
    pub ecdh_infos: Vec<Vec<u8>>,
    /// Serialized range proofs (Bulletproof+, without the `V` vector), one per batch.
    pub range_proofs: Vec<Vec<u8>>,
    /// Transaction `extra`.
    pub extra: Vec<u8>,
    /// Transaction prefix hash computed by the device.
    pub tx_prefix_hash: Vec<u8>,
    /// Pre-CLSAG message hash computed by the device.
    pub full_message_hash: Vec<u8>,
    /// RingCT type (6 = CLSAG + Bulletproof+).
    pub rv_type: u32,
    /// Fee.
    pub fee: u64,
    /// Master key for opening the sealed signatures.
    pub opening_key: Vec<u8>,
    /// Encrypted transaction private keys (opaque; decryptable only with the spend key).
    pub tx_enc_keys: Vec<u8>,
    /// Salt for `tx_enc_keys`.
    pub salt: Vec<u8>,
    /// Random multiplier for `tx_enc_keys`.
    pub rand_mult: Vec<u8>,
}

/// Drive a response to completion: confirmation prompts (`ButtonRequest`) are acknowledged and
/// confirmed by the user on the device. A `PassphraseRequest` is NOT answered (answering
/// "on device" would leave the device waiting on its keyboard): unlock the passphrase session
/// first, e.g. by answering the first request of the session with `ack_passphrase`.
fn drive<T, R: crate::messages::TrezorMessage>(resp: TrezorResponse<'_, T, R>) -> Result<T> {
    match resp {
        TrezorResponse::Ok(v) => Ok(v),
        TrezorResponse::Failure(_) => resp.ok(),
        TrezorResponse::ButtonRequest(req) => drive(req.ack()?),
        TrezorResponse::PinMatrixRequest(_) => {
            Err(Error::UnexpectedInteractionRequest(InteractionType::PinMatrix))
        }
        TrezorResponse::PassphraseRequest(_) => {
            Err(Error::UnexpectedInteractionRequest(InteractionType::Passphrase))
        }
    }
}
fn monero_error(msg: impl Into<String>) -> Error {
    Error::InvalidMoneroTransaction(msg.into())
}

impl Trezor {
    /// Get a Monero address. `(account, minor) == (0, 0)` is the primary address; anything else
    /// is a subaddress.
    pub fn monero_get_address(
        &mut self,
        address_n: Vec<u32>,
        network_type: MoneroNetworkType,
        account: u32,
        minor: u32,
        show_display: bool,
    ) -> Result<String> {
        let mut req = protos::MoneroGetAddress::new();
        req.address_n = address_n;
        req.set_network_type(network_type);
        req.set_account(account);
        req.set_minor(minor);
        req.set_show_display(show_display);
        let bytes = drive(
            self.call(req, Box::new(|_, m: protos::MoneroAddress| Ok(m.address().to_vec())))?,
        )?;
        String::from_utf8(bytes).map_err(|_| monero_error("address is not UTF-8"))
    }

    /// Export the account's private view key and primary address (requires confirmation on the
    /// device). The spend key never leaves the device.
    pub fn monero_get_watch_key(
        &mut self,
        address_n: Vec<u32>,
        network_type: MoneroNetworkType,
    ) -> Result<MoneroWatchKey> {
        let mut req = protos::MoneroGetWatchKey::new();
        req.address_n = address_n;
        req.set_network_type(network_type);
        let m = drive(self.call(req, Box::new(|_, m: protos::MoneroWatchKey| Ok(m)))?)?;
        let address = String::from_utf8(m.address().to_vec())
            .map_err(|_| monero_error("address is not UTF-8"))?;
        Ok(MoneroWatchKey { watch_key: m.watch_key().to_vec(), address })
    }

    /// Run the key image sync protocol for `transfers` (requires confirmation on the device).
    ///
    /// `transfers_hash` must be `keccak256(H(t_0) || H(t_1) || ...)` where
    /// `H(t) = keccak256(out_key || tx_pub_key || additional_tx_pub_keys... || varint(internal_output_index))`;
    /// the device aborts if it doesn't match. Transfers are sent `batch_size` at a time.
    pub fn monero_key_image_sync(
        &mut self,
        address_n: Vec<u32>,
        network_type: MoneroNetworkType,
        subs: Vec<MoneroSubAddressIndicesList>,
        transfers: Vec<MoneroTransferDetails>,
        transfers_hash: Vec<u8>,
        batch_size: usize,
    ) -> Result<MoneroKeyImageSyncResult> {
        if transfers.is_empty() {
            return Err(monero_error("key image sync needs at least one transfer"));
        }
        let mut init = protos::MoneroKeyImageExportInitRequest::new();
        init.set_num(transfers.len() as u64);
        init.set_hash(transfers_hash);
        init.address_n = address_n;
        init.set_network_type(network_type);
        init.subs = subs;
        drive(self.call(init, Box::new(|_, _: protos::MoneroKeyImageExportInitAck| Ok(())))?)?;

        let mut key_images = Vec::with_capacity(transfers.len());
        for chunk in transfers.chunks(batch_size.max(1)) {
            let mut step = protos::MoneroKeyImageSyncStepRequest::new();
            step.tdis = chunk.to_vec();
            let ack =
                drive(self.call(step, Box::new(|_, m: protos::MoneroKeyImageSyncStepAck| Ok(m)))?)?;
            if ack.kis.len() != chunk.len() {
                return Err(monero_error("device returned a wrong number of key images"));
            }
            key_images.extend(ack.kis);
        }

        let fin = drive(self.call(
            protos::MoneroKeyImageSyncFinalRequest::new(),
            Box::new(|_, m: protos::MoneroKeyImageSyncFinalAck| Ok(m)),
        )?)?;
        Ok(MoneroKeyImageSyncResult { key_images, enc_key: fin.enc_key().to_vec() })
    }

    /// Sign a Monero transaction (the device asks the user to confirm destinations and fee).
    ///
    /// Drives the full protocol: `TransactionInit`, `SetInput` per input, key-image sorting,
    /// `InputVini` per input, `AllInputsSet`, `SetOutput` per output, `AllOutSet`, `SignInput`
    /// per input and `Final`. Only the two-output shape (destination + change, or a sweep with a
    /// zero change output) is supported, for which the device computes the range proof itself.
    pub fn monero_sign_tx(&mut self, request: MoneroSignTxRequest) -> Result<MoneroSignedTxParts> {
        let MoneroSignTxRequest { address_n, network_type, mut tsx_data, inputs } = request;
        let n_in = inputs.len();
        let n_out = tsx_data.outputs.len();
        if n_in == 0 {
            return Err(monero_error("no inputs"));
        }
        if n_out != 2 {
            return Err(monero_error("only two-output transactions are supported"));
        }
        tsx_data.set_num_inputs(n_in as u32);
        let outputs: Vec<MoneroTransactionDestinationEntry> = tsx_data.outputs.clone();

        // 1. Init (user confirmation happens here).
        let mut init = protos::MoneroTransactionInitRequest::new();
        init.set_version(0);
        init.address_n = address_n;
        init.set_network_type(network_type);
        init.tsx_data = MessageField::some(tsx_data);
        let init_ack =
            drive(self.call(init, Box::new(|_, m: protos::MoneroTransactionInitAck| Ok(m)))?)?;
        if init_ack.hmacs.len() != n_out {
            return Err(monero_error("device returned a wrong number of output HMACs"));
        }
        if init_ack.rsig_data.as_ref().map_or(false, |r| r.offload_type() != 0) {
            return Err(monero_error("device requested offloaded range proofs"));
        }

        // 2. SetInput, original order.
        struct In {
            vini: Vec<u8>,
            vini_hmac: Vec<u8>,
            pseudo_out: Vec<u8>,
            pseudo_out_hmac: Vec<u8>,
            alpha_enc: Vec<u8>,
            spend_enc: Vec<u8>,
        }
        let mut ins = Vec::with_capacity(n_in);
        for src in &inputs {
            let mut req = protos::MoneroTransactionSetInputRequest::new();
            req.src_entr = MessageField::some(src.clone());
            let ack = drive(
                self.call(req, Box::new(|_, m: protos::MoneroTransactionSetInputAck| Ok(m)))?,
            )?;
            if ack.vini().len() < 32 {
                return Err(monero_error("malformed vin from device"));
            }
            ins.push(In {
                vini: ack.vini().to_vec(),
                vini_hmac: ack.vini_hmac().to_vec(),
                pseudo_out: ack.pseudo_out().to_vec(),
                pseudo_out_hmac: ack.pseudo_out_hmac().to_vec(),
                alpha_enc: ack.pseudo_out_alpha().to_vec(),
                spend_enc: ack.spend_key().to_vec(),
            });
        }

        // 3. Sort inputs by key image (the vin's last 32 bytes), descending, as Monero requires.
        let mut permutation: Vec<usize> = (0..n_in).collect();
        permutation.sort_by(|&a, &b| {
            let ka = &ins[a].vini[ins[a].vini.len() - 32..];
            let kb = &ins[b].vini[ins[b].vini.len() - 32..];
            kb.cmp(ka)
        });

        // 4. InputVini, sorted order.
        for &orig in &permutation {
            let i = &ins[orig];
            let mut req = protos::MoneroTransactionInputViniRequest::new();
            req.src_entr = MessageField::some(inputs[orig].clone());
            req.set_vini(i.vini.clone());
            req.set_vini_hmac(i.vini_hmac.clone());
            req.set_pseudo_out(i.pseudo_out.clone());
            req.set_pseudo_out_hmac(i.pseudo_out_hmac.clone());
            req.set_orig_idx(orig as u32);
            drive(self.call(req, Box::new(|_, _: protos::MoneroTransactionInputViniAck| Ok(())))?)?;
        }

        // 5. AllInputsSet.
        drive(self.call(
            protos::MoneroTransactionAllInputsSetRequest::new(),
            Box::new(|_, _: protos::MoneroTransactionAllInputsSetAck| Ok(())),
        )?)?;

        // 6. SetOutput per output.
        let mut tx_outs = Vec::with_capacity(n_out);
        let mut out_pks = Vec::with_capacity(n_out);
        let mut ecdh_infos = Vec::with_capacity(n_out);
        let mut range_proofs = Vec::new();
        for (idx, dst) in outputs.iter().enumerate() {
            let mut req = protos::MoneroTransactionSetOutputRequest::new();
            req.dst_entr = MessageField::some(dst.clone());
            req.set_dst_entr_hmac(init_ack.hmacs[idx].clone());
            let ack = drive(
                self.call(req, Box::new(|_, m: protos::MoneroTransactionSetOutputAck| Ok(m)))?,
            )?;
            if ack.out_pk().len() != 64 || ack.ecdh_info().len() != 8 {
                return Err(monero_error("malformed output from device"));
            }
            tx_outs.push(ack.tx_out().to_vec());
            out_pks.push(ack.out_pk().to_vec());
            ecdh_infos.push(ack.ecdh_info().to_vec());
            if let Some(rsig) = ack.rsig_data.as_ref() {
                if !rsig.rsig().is_empty() {
                    range_proofs.push(rsig.rsig().to_vec());
                }
            }
        }
        if range_proofs.len() != 1 {
            return Err(monero_error("expected exactly one range proof from the device"));
        }

        // 7. AllOutSet.
        let all_out = drive(self.call(
            protos::MoneroTransactionAllOutSetRequest::new(),
            Box::new(|_, m: protos::MoneroTransactionAllOutSetAck| Ok(m)),
        )?)?;
        let rv = all_out.rv.as_ref().ok_or_else(|| monero_error("missing RingCT header"))?;
        let (fee, rv_type) = (rv.txn_fee(), rv.rv_type());

        // 8. SignInput, sorted order.
        let mut pseudo_outs = Vec::with_capacity(n_in);
        let mut signatures = Vec::with_capacity(n_in);
        for &orig in &permutation {
            let i = &ins[orig];
            let mut req = protos::MoneroTransactionSignInputRequest::new();
            req.src_entr = MessageField::some(inputs[orig].clone());
            req.set_vini(i.vini.clone());
            req.set_vini_hmac(i.vini_hmac.clone());
            req.set_pseudo_out(i.pseudo_out.clone());
            req.set_pseudo_out_hmac(i.pseudo_out_hmac.clone());
            req.set_pseudo_out_alpha(i.alpha_enc.clone());
            req.set_spend_key(i.spend_enc.clone());
            req.set_orig_idx(orig as u32);
            let ack = drive(
                self.call(req, Box::new(|_, m: protos::MoneroTransactionSignInputAck| Ok(m)))?,
            )?;
            signatures.push(ack.signature().to_vec());
            pseudo_outs.push(if ack.has_pseudo_out() {
                ack.pseudo_out().to_vec()
            } else {
                i.pseudo_out.clone()
            });
        }

        // 9. Final.
        let fin = drive(self.call(
            protos::MoneroTransactionFinalRequest::new(),
            Box::new(|_, m: protos::MoneroTransactionFinalAck| Ok(m)),
        )?)?;
        if fin.opening_key().len() != 32 {
            return Err(monero_error("device did not release the signature opening key"));
        }

        Ok(MoneroSignedTxParts {
            vins: permutation.iter().map(|&o| ins[o].vini.clone()).collect(),
            permutation,
            pseudo_outs,
            signatures,
            tx_outs,
            out_pks,
            ecdh_infos,
            range_proofs,
            extra: all_out.extra().to_vec(),
            tx_prefix_hash: all_out.tx_prefix_hash().to_vec(),
            full_message_hash: all_out.full_message_hash().to_vec(),
            rv_type,
            fee,
            opening_key: fin.opening_key().to_vec(),
            tx_enc_keys: fin.tx_enc_keys().to_vec(),
            salt: fin.salt().to_vec(),
            rand_mult: fin.rand_mult().to_vec(),
        })
    }
}
