use super::{Trezor, TrezorResponse};
use crate::{
    error::{Error, Result},
    flows::sign_tx::SignTxProgress,
    protos, utils,
};
use bitcoin::{
    address::NetworkUnchecked, bip32, network::Network, psbt,
    secp256k1::ecdsa::RecoverableSignature, Address,
};

pub use crate::protos::InputScriptType;

// The `*_coin` variants take the device's `coin_name` (e.g. "Litecoin") instead of a Bitcoin
// `Network`, for the other Bitcoin-like coins the firmware supports. Their results don't go
// through rust-bitcoin's address and xpub parsers, which only know Bitcoin's formats.
impl Trezor {
    pub fn get_public_key(
        &mut self,
        path: &bip32::DerivationPath,
        network: Network,
        show_display: bool,
    ) -> Result<TrezorResponse<'_, bip32::Xpub, protos::PublicKey>> {
        let req = public_key_request(path, &utils::coin_name(network)?, show_display);
        self.call(req, Box::new(|_, m| Ok(m.xpub().parse()?)))
    }

    /// The extended public key at `path` for the coin `coin_name`. It is built from the
    /// returned HD node, so the coin's version bytes (e.g. `Ltub`) don't matter; its `network`
    /// is always `NetworkKind::Main`.
    pub fn get_public_key_coin(
        &mut self,
        path: &bip32::DerivationPath,
        coin_name: &str,
        show_display: bool,
    ) -> Result<TrezorResponse<'_, bip32::Xpub, protos::PublicKey>> {
        let req = public_key_request(path, coin_name, show_display);
        self.call(req, Box::new(|_, m| xpub_from_node(&m.node)))
    }

    //TODO(stevenroose) multisig
    pub fn get_address(
        &mut self,
        path: &bip32::DerivationPath,
        script_type: InputScriptType,
        network: Network,
        show_display: bool,
    ) -> Result<TrezorResponse<'_, Address, protos::Address>> {
        let req = address_request(path, script_type, &utils::coin_name(network)?, show_display);
        self.call(req, Box::new(|_, m| parse_address(m.address())))
    }

    /// The address at `path` for the coin `coin_name`, as the device encodes it.
    pub fn get_address_coin(
        &mut self,
        path: &bip32::DerivationPath,
        script_type: InputScriptType,
        coin_name: &str,
        show_display: bool,
    ) -> Result<TrezorResponse<'_, String, protos::Address>> {
        let req = address_request(path, script_type, coin_name, show_display);
        self.call(req, Box::new(|_, m: protos::Address| Ok(m.address().to_owned())))
    }

    /// The address at `path` with its SLIP-24 MAC (proof to the device that the
    /// address is its own, for payment requests). Not displayed.
    pub fn get_address_mac(
        &mut self,
        path: &bip32::DerivationPath,
        script_type: InputScriptType,
        network: Network,
    ) -> Result<TrezorResponse<'_, (String, Vec<u8>), protos::Address>> {
        self.get_address_mac_coin(path, script_type, &utils::coin_name(network)?)
    }

    /// [`Self::get_address_mac`] for the coin `coin_name`.
    pub fn get_address_mac_coin(
        &mut self,
        path: &bip32::DerivationPath,
        script_type: InputScriptType,
        coin_name: &str,
    ) -> Result<TrezorResponse<'_, (String, Vec<u8>), protos::Address>> {
        let req = address_request(path, script_type, coin_name, false);
        self.call(
            req,
            Box::new(|_, m: protos::Address| Ok((m.address().to_owned(), m.mac().to_vec()))),
        )
    }

    pub fn sign_tx(
        &mut self,
        psbt: &psbt::Psbt,
        network: Network,
    ) -> Result<TrezorResponse<'_, SignTxProgress<'_>, protos::TxRequest>> {
        self.sign_tx_coin(psbt, &utils::coin_name(network)?)
    }

    /// [`Self::sign_tx`] for the coin `coin_name`. Answer the device's requests with
    /// [`SignTxProgress::ack_psbt_with`] and an encoder for that coin's addresses.
    pub fn sign_tx_coin(
        &mut self,
        psbt: &psbt::Psbt,
        coin_name: &str,
    ) -> Result<TrezorResponse<'_, SignTxProgress<'_>, protos::TxRequest>> {
        let tx = &psbt.unsigned_tx;
        let mut req = protos::SignTx::new();
        req.set_inputs_count(tx.input.len() as u32);
        req.set_outputs_count(tx.output.len() as u32);
        req.set_coin_name(coin_name.to_owned());
        req.set_version(tx.version.0 as u32);
        req.set_lock_time(tx.lock_time.to_consensus_u32());
        self.call(req, Box::new(|c, m| Ok(SignTxProgress::new(c, m))))
    }

    pub fn sign_message(
        &mut self,
        message: String,
        path: &bip32::DerivationPath,
        script_type: InputScriptType,
        network: Network,
    ) -> Result<TrezorResponse<'_, (Address, RecoverableSignature), protos::MessageSignature>> {
        let mut req = protos::SignMessage::new();
        req.address_n = utils::convert_path(path);
        // Normalize to Unicode NFC.
        let msg_bytes = nfc_normalize(&message).into_bytes();
        req.set_message(msg_bytes);
        req.set_coin_name(utils::coin_name(network)?);
        req.set_script_type(script_type);
        self.call(
            req,
            Box::new(|_, m| {
                let address = parse_address(m.address())?;
                let signature = utils::parse_recoverable_signature(m.signature())?;
                Ok((address, signature))
            }),
        )
    }
}

fn parse_address(s: &str) -> Result<Address> {
    let address = s.parse::<Address<NetworkUnchecked>>()?;
    Ok(address.assume_checked())
}

// Modified from:
// https://github.com/rust-lang/rust/blob/2a8221dbdfd180a2d56d4b0089f4f3952d8c2bcd/compiler/rustc_parse/src/lexer/mod.rs#LL754C5-L754C5
fn nfc_normalize(string: &str) -> String {
    use unicode_normalization::{is_nfc_quick, IsNormalized, UnicodeNormalization};
    match is_nfc_quick(string.chars()) {
        IsNormalized::Yes => string.to_string(),
        _ => string.chars().nfc().collect::<String>(),
    }
}

fn public_key_request(
    path: &bip32::DerivationPath,
    coin_name: &str,
    show_display: bool,
) -> protos::GetPublicKey {
    let mut req = protos::GetPublicKey::new();
    req.address_n = utils::convert_path(path);
    req.set_show_display(show_display);
    req.set_coin_name(coin_name.to_owned());
    req
}

fn address_request(
    path: &bip32::DerivationPath,
    script_type: InputScriptType,
    coin_name: &str,
    show_display: bool,
) -> protos::GetAddress {
    let mut req = protos::GetAddress::new();
    req.address_n = utils::convert_path(path);
    req.set_coin_name(coin_name.to_owned());
    req.set_show_display(show_display);
    req.set_script_type(script_type);
    req
}

/// An `Xpub` from the device's HD node (whose `fingerprint` is the parent's), independent of
/// the coin's version bytes.
fn xpub_from_node(node: &protos::HDNodeType) -> Result<bip32::Xpub> {
    let depth = u8::try_from(node.depth())
        .map_err(|_| Error::Bip32(bip32::Error::InvalidDerivationPathFormat))?;
    let chain_code = <[u8; 32]>::try_from(node.chain_code())
        .map_err(|_| Error::Bip32(bip32::Error::WrongExtendedKeyLength(node.chain_code().len())))?;
    Ok(bip32::Xpub {
        network: bitcoin::NetworkKind::Main,
        depth,
        parent_fingerprint: bip32::Fingerprint::from(node.fingerprint().to_be_bytes()),
        child_number: bip32::ChildNumber::from(node.child_num()),
        public_key: bitcoin::secp256k1::PublicKey::from_slice(node.public_key())?,
        chain_code: bip32::ChainCode::from(chain_code),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    // Trezor's `test_getpublickey.py` vector for Litecoin m/44h/2h/0h (mnemonic "all" x12):
    // the node behind the device's `Ltub` must give the same key as the `Ltub` re-versioned to
    // `xpub`.
    #[test]
    fn xpub_from_litecoin_node() {
        let ltub = "Ltub2Y8PyEMWQVgiX4L4gVzU8PakBTQ2WBxFdS6tJARQeasUUfXmBut2jGShnQyD3jgyBf7mmvs5jPNgmgXad5J6M8a8FiZK78dbT21fYtTAC9a";
        let mut data = bitcoin::base58::decode_check(ltub).unwrap();
        assert_eq!(data[..4], [0x01, 0x9d, 0xa4, 0x62]);
        let mut node = protos::HDNodeType::new();
        node.set_depth(data[4].into());
        node.set_fingerprint(u32::from_be_bytes(data[5..9].try_into().unwrap()));
        node.set_child_num(u32::from_be_bytes(data[9..13].try_into().unwrap()));
        node.set_chain_code(data[13..45].to_vec());
        node.set_public_key(data[45..78].to_vec());

        data[..4].copy_from_slice(&[0x04, 0x88, 0xb2, 0x1e]);
        let expected = bip32::Xpub::from_str(&bitcoin::base58::encode_check(&data)).unwrap();
        assert_eq!(xpub_from_node(&node).unwrap(), expected);
        assert_eq!(expected.depth, 3);
        assert_eq!(expected.child_number, bip32::ChildNumber::from_hardened_idx(0).unwrap());
    }

    #[test]
    fn xpub_from_bad_node() {
        let mut node = protos::HDNodeType::new();
        node.set_chain_code(vec![0; 31]);
        node.set_public_key(vec![2; 33]);
        assert!(xpub_from_node(&node).is_err());
        node.set_chain_code(vec![0; 32]);
        node.set_public_key(vec![9; 33]);
        assert!(xpub_from_node(&node).is_err());
    }
}
