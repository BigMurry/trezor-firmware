use alloy_primitives::Address;
use paste::paste;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::{handle_interaction, Trezor};
use crate::{
    debug,
    error::Result,
    protos::{
        self,
        ethereum_sign_tx_eip1559::EthereumAccessList,
        ethereum_typed_data_struct_ack::{EthereumDataType, EthereumFieldType},
        EthereumTxRequest, MessageType,
    },
    Error,
};

/// Access list item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessListItem {
    /// Accessed address
    pub address: String,
    /// Accessed storage keys
    pub storage_keys: Vec<Vec<u8>>,
}

/// An ECDSA signature.
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub struct Signature {
    /// R value
    pub r: [u8; 32],
    /// S Value
    pub s: [u8; 32],
    /// V value in 'Electrum' notation.
    pub v: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NameType {
    pub name: String,
    pub r#type: String,
}

pub struct Eip712TypedData {
    pub types: BTreeMap<String, Vec<NameType>>,
    pub primary_type: String,
    pub domain: serde_json::Value,
    pub message: serde_json::Value,
}

macro_rules! impl_de_uint {
    ($($size:literal),+$(,)?) => {
        fn serde_number_to_bytes(size: u32, value: serde_json::Value, signed: bool) -> Result<Vec<u8>> {
            match size {
                $($size => {paste!{
                    if signed {
                        let v = serde_json::from_value::<::alloy_primitives::aliases::[<I $size>]>(value)
                            .map_err(|_| Error::Eip712Err("invalid int format".to_owned()))?;
                        Ok(v.to_be_bytes::<{::alloy_primitives::aliases::[<I $size>]::BYTES}>().to_vec())
                    } else {
                        let v = serde_json::from_value::<::alloy_primitives::aliases::[<U $size>]>(value)
                            .map_err(|_| Error::Eip712Err("invalid uint format".to_owned()))?;
                        Ok(v.to_be_bytes::<{::alloy_primitives::aliases::[<U $size>]::BYTES}>().to_vec())
                    }
                }})+
                _ => Err(Error::Eip712Err(format!("int size {} not supported", size)))
            }
        }
    };
}

impl_de_uint! {8,16,24,32,40,48,56,64,72,80,88,96,104,112,120,128,136,144,152,160,168,176,184,192,200,208,216,224,232,240,248,256}

fn encode_data(value: serde_json::Value, type_name: &str) -> Result<Vec<u8>> {
    let bytes = if type_name.starts_with("bytes") {
        let bytes = serde_json::from_value::<alloy_primitives::Bytes>(value)
            .map_err(|_| Error::Eip712Err("invalid json bytes format".to_owned()))?;
        bytes.to_vec()
    } else if type_name == "string" {
        let value = serde_json::from_value::<String>(value)
            .map_err(|_| Error::Eip712Err("invalid json string format".to_owned()))?;
        value.as_bytes().to_vec()
    } else if type_name.starts_with("int") || type_name.starts_with("uint") {
        let int_size = get_int_size(type_name)?;
        serde_number_to_bytes(int_size * 8, value, type_name.starts_with("int"))?
    } else if type_name == "bool" {
        let value = serde_json::from_value::<bool>(value)
            .map_err(|_| Error::Eip712Err("invalid json bool format".to_owned()))?
            as u8;
        value.to_be_bytes().to_vec()
    } else if type_name == "address" {
        let value = serde_json::from_value::<Address>(value)
            .map_err(|_| Error::Eip712Err("invalid json address format".to_owned()))?;
        value.to_vec()
    } else {
        return Err(Error::Eip712Err("type value not supported".to_owned()));
    };

    Ok(bytes)
}

fn get_int_size(type_name: &str) -> Result<u32> {
    let idx = type_name.find("t").unwrap();
    Ok(type_name[idx + 1..]
        .parse::<u32>()
        .map_err(|_| Error::Eip712Err("invalid uint type, can not get it's size".to_owned()))?
        / 8)
}

impl Eip712TypedData {
    fn get_eip712_field_type(&self, type_name: &str) -> Result<EthereumFieldType> {
        let mut data_field = EthereumFieldType::new();
        let l_bra_idx = type_name.find('[');
        let r_bra_idx = type_name.find(']');
        if let (Some(l_idx), Some(r_idx)) = (l_bra_idx, r_bra_idx) {
            data_field.set_data_type(EthereumDataType::ARRAY);
            if l_idx != r_idx {
                let size = type_name[l_idx + 1..r_idx]
                    .parse::<u32>()
                    .map_err(|_| Error::Eip712Err("invalid array type, size invalid".to_owned()))?;
                data_field.set_size(size);
            }

            let entry_type = self.get_eip712_field_type(&type_name[..l_idx])?;
            if matches!(entry_type.data_type(), EthereumDataType::ARRAY) {
                return Err(Error::Eip712Err("nested array not supported".to_owned()));
            }
            data_field.entry_type = protobuf::MessageField::some(entry_type);
        } else if type_name.starts_with("uint") {
            data_field.set_data_type(EthereumDataType::UINT);
            if type_name == "uint" {
                data_field.set_size(32);
            } else {
                data_field.set_size(get_int_size(type_name)?);
            }
        } else if type_name.starts_with("int") {
            data_field.set_data_type(EthereumDataType::INT);
            if type_name == "int" {
                data_field.set_size(32);
            } else {
                data_field.set_size(get_int_size(type_name)?);
            }
        } else if type_name.starts_with("bytes") {
            data_field.set_data_type(EthereumDataType::BYTES);
            if type_name != "bytes" {
                let idx = type_name.find("s").unwrap();
                let size = type_name[idx + 1..].parse::<u32>().map_err(|_| {
                    Error::Eip712Err("invalid bytes type, can not get it's size".to_owned())
                })? / 8;
                data_field.set_size(size);
            }
        } else if type_name == "string" {
            data_field.set_data_type(EthereumDataType::STRING);
        } else if type_name == "bool" {
            data_field.set_data_type(EthereumDataType::BOOL);
        } else if type_name == "address" {
            data_field.set_data_type(EthereumDataType::ADDRESS);
        } else if let Some(name_tys) = self.types.get(type_name) {
            data_field.set_data_type(EthereumDataType::STRUCT);
            data_field.set_size(name_tys.len().try_into().map_err(|_| {
                Error::Eip712Err(format!("invalid types len for key: {type_name}"))
            })?);
        } else {
            return Err(Error::Eip712Err(format!("unsupported eip712 type: {type_name}")));
        }

        Ok(data_field)
    }

    fn get_712_struct_ty_ack(
        &self,
        struct_name: &str,
    ) -> Result<protos::EthereumTypedDataStructAck> {
        let mut ack = protos::EthereumTypedDataStructAck::new();
        let struct_tys = self
            .types
            .get(struct_name)
            .ok_or(Error::Eip712Err(format!("struct with name: {struct_name} not found")))?;
        for field in struct_tys.iter() {
            debug!("712 get struct field ty ack: {}, {}", &field.name, &field.r#type);
            let mut member = protos::ethereum_typed_data_struct_ack::EthereumStructMember::new();
            let field_type = self.get_eip712_field_type(&field.r#type)?;
            debug!("712 get struct field ty ack: {}, {} ok", &field.name, &field.r#type);
            member.type_ = protobuf::MessageField::some(field_type);
            member.set_name(field.name.to_owned());
            ack.members.push(member);
        }
        Ok(ack)
    }

    fn get_712_struct_value_ack(
        &self,
        member_path: &[u32],
    ) -> Result<protos::EthereumTypedDataValueAck> {
        if member_path.is_empty() {
            return Err(Error::Eip712Err("typed data value request member path empty".to_owned()));
        }
        let root_idx = member_path[0];
        let (mut member_type, mut member_data) = if root_idx == 0 {
            ("EIP712Domain", &self.domain)
        } else if root_idx == 1 {
            (self.primary_type.as_ref(), &self.message)
        } else {
            return Err(Error::Eip712Err(
                "typed data value request root index can only be 0 or 1".to_owned(),
            ));
        };

        debug!("712 get struct field value ack member path scan...");
        for idx in member_path[1..].iter() {
            if member_data.is_object() {
                let member_def = self
                    .types
                    .get(member_type)
                    .ok_or(Error::Eip712Err(format!("type {member_type} not found in types")))?
                    .get(*idx as usize)
                    .ok_or(Error::Eip712Err(format!("type index {idx} out of types range")))?;

                member_type = member_def.r#type.as_ref();
                member_data = member_data.get(&member_def.name).ok_or(Error::Eip712Err(
                    format!("member {} not found in data", &member_def.name),
                ))?;
            } else if member_data.is_array() {
                let l_bra_idx = member_type.find("[").ok_or(Error::Eip712Err(format!(
                    "invalid member type {member_type}, `[` not found",
                )))?;
                member_type = &member_type[..l_bra_idx];
                member_data = member_data.get(*idx as usize).ok_or(Error::Eip712Err(format!(
                    "member value of index {idx} not found in data"
                )))?;
            }
        }

        debug!("712 get struct field value ack: {}, {:?} ok", &member_type, &member_data);
        let data = if member_data.is_array() {
            let size = member_data.as_array().unwrap().len() as u16;
            size.to_be_bytes().to_vec()
        } else {
            debug!("712 get struct field value ack: encode_data");
            encode_data(member_data.clone(), member_type)?
        };

        debug!("712 get struct field value ack: encode_data done: {:?}", &data);
        let mut req = protos::EthereumTypedDataValueAck::new();
        req.set_value(data);
        Ok(req)
    }
}

impl Trezor {
    // ETHEREUM
    pub fn ethereum_get_address(&mut self, path: Vec<u32>) -> Result<String> {
        let mut req = protos::EthereumGetAddress::new();
        req.address_n = path;
        let address = handle_interaction(
            self.call(req, Box::new(|_, m: protos::EthereumAddress| Ok(m.address().into())))?,
        )?;
        Ok(address)
    }

    pub fn ethereum_sign_message(&mut self, message: Vec<u8>, path: Vec<u32>) -> Result<Signature> {
        let mut req = protos::EthereumSignMessage::new();
        req.address_n = path;
        req.set_message(message);
        let signature = handle_interaction(self.call(
            req,
            Box::new(|_, m: protos::EthereumMessageSignature| {
                let signature = m.signature();
                if signature.len() != 65 {
                    return Err(Error::MalformedSignature);
                }
                let r = signature[0..32].try_into().unwrap();
                let s = signature[32..64].try_into().unwrap();
                let v = signature[64] as u64;
                Ok(Signature { r, s, v })
            }),
        )?)?;

        Ok(signature)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn ethereum_sign_tx(
        &mut self,
        path: Vec<u32>,
        nonce: Vec<u8>,
        gas_price: Vec<u8>,
        gas_limit: Vec<u8>,
        to: String,
        value: Vec<u8>,
        data: Vec<u8>,
        chain_id: Option<u64>,
    ) -> Result<Signature> {
        let mut req = protos::EthereumSignTx::new();
        let mut data = data;

        req.address_n = path;
        req.set_nonce(nonce);
        req.set_gas_price(gas_price);
        req.set_gas_limit(gas_limit);
        req.set_value(value);
        if let Some(chain_id) = chain_id {
            req.set_chain_id(chain_id);
        }
        req.set_to(to);

        req.set_data_length(data.len() as u32);
        req.set_data_initial_chunk(data.splice(..std::cmp::min(1024, data.len()), []).collect());

        let mut resp =
            handle_interaction(self.call(req, Box::new(|_, m: protos::EthereumTxRequest| Ok(m)))?)?;

        while resp.data_length() > 0 {
            let mut ack = protos::EthereumTxAck::new();
            ack.set_data_chunk(data.splice(..std::cmp::min(1024, data.len()), []).collect());

            resp = self.call(ack, Box::new(|_, m: protos::EthereumTxRequest| Ok(m)))?.ok()?;
        }

        convert_signature(&resp, chain_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn ethereum_sign_eip1559_tx(
        &mut self,
        path: Vec<u32>,
        nonce: Vec<u8>,
        gas_limit: Vec<u8>,
        to: String,
        value: Vec<u8>,
        data: Vec<u8>,
        chain_id: Option<u64>,
        max_gas_fee: Vec<u8>,
        max_priority_fee: Vec<u8>,
        access_list: Vec<AccessListItem>,
    ) -> Result<Signature> {
        let mut req = protos::EthereumSignTxEIP1559::new();
        let mut data = data;

        req.address_n = path;
        req.set_nonce(nonce);
        req.set_max_gas_fee(max_gas_fee);
        req.set_max_priority_fee(max_priority_fee);
        req.set_gas_limit(gas_limit);
        req.set_value(value);
        if let Some(chain_id) = chain_id {
            req.set_chain_id(chain_id);
        }
        req.set_to(to);

        if !access_list.is_empty() {
            req.access_list = access_list
                .into_iter()
                .map(|item| EthereumAccessList {
                    address: Some(item.address),
                    storage_keys: item.storage_keys,
                    ..Default::default()
                })
                .collect();
        }

        req.set_data_length(data.len() as u32);
        req.set_data_initial_chunk(data.splice(..std::cmp::min(1024, data.len()), []).collect());

        let mut resp =
            handle_interaction(self.call(req, Box::new(|_, m: protos::EthereumTxRequest| Ok(m)))?)?;

        while resp.data_length() > 0 {
            let mut ack = protos::EthereumTxAck::new();
            ack.set_data_chunk(data.splice(..std::cmp::min(1024, data.len()), []).collect());

            resp = self.call(ack, Box::new(|_, m: protos::EthereumTxRequest| Ok(m)))?.ok()?
        }

        convert_signature(&resp, chain_id)
    }

    pub fn ethereum_sign_eip712_data(
        &mut self,
        path: Vec<u32>,
        data: Eip712TypedData,
        metamask_v4_compat: bool,
        show_message_hash: Option<Vec<u8>>,
    ) -> Result<Signature> {
        let mut req = protos::EthereumSignTypedData::new();
        req.address_n = path;
        req.set_primary_type(data.primary_type.clone());
        req.set_metamask_v4_compat(metamask_v4_compat);
        if let Some(message_hash) = show_message_hash {
            req.set_show_message_hash(message_hash);
        }

        let mut resp = handle_interaction(
            self.call(req, Box::new(|_, m: protos::EthereumTypedDataStructRequest| Ok(m)))?,
        );

        let value_request = loop {
            match resp {
                Ok(rep) => {
                    debug!("712 ty ack: {}", &rep.name());
                    let req = data.get_712_struct_ty_ack(rep.name())?;
                    resp = handle_interaction(self.call(
                        req,
                        Box::new(|_, m: protos::EthereumTypedDataStructRequest| Ok(m)),
                    )?);
                }
                Err(Error::UnhandledMessage(
                    MessageType::MessageType_EthereumTypedDataValueRequest,
                    raw,
                )) => {
                    debug!("712 ty ack unhandle msg");
                    break raw;
                }
                Err(err) => {
                    debug!("712 ty ack unknown error: {:?}", &err);
                    return Err(err);
                }
            }
        };

        debug!("712 try parse data value req");
        let mut value_resp: Result<protos::EthereumTypedDataValueRequest> =
            protobuf::Message::parse_from_bytes(&value_request)
                .map_err(|_| Error::Eip712Err("invalid eip712 value req".to_owned()));

        debug!("712 try parse data value req: ok");
        let sig_bytes = loop {
            match value_resp {
                Ok(rep) => {
                    debug!("712 data value ack: {:?}", &rep.member_path);
                    let req = data.get_712_struct_value_ack(&rep.member_path)?;
                    value_resp = handle_interaction(self.call(
                        req,
                        Box::new(|_, m: protos::EthereumTypedDataValueRequest| Ok(m)),
                    )?);
                }
                Err(Error::UnhandledMessage(
                    MessageType::MessageType_EthereumTypedDataSignature,
                    raw,
                )) => {
                    debug!("712 data value unhandle msg");
                    break raw;
                }
                Err(err) => {
                    debug!("712 value ack unknown error: {:?}", &err);
                    return Err(err);
                }
            }
        };

        debug!("712 try parse signature value req");
        let sig: protos::EthereumTypedDataSignature =
            protobuf::Message::parse_from_bytes(&sig_bytes)
                .map_err(|_| Error::Eip712Err("invalid eip127 final signature type".to_owned()))?;
        debug!("712 try parse signature value req: ok");

        let signature = sig.signature();
        if signature.len() != 65 {
            debug!("712 signature invalid: {:?}", &signature);
            return Err(Error::MalformedSignature);
        }
        let r = signature[0..32].try_into().unwrap();
        let s = signature[32..64].try_into().unwrap();
        let v = signature[64] as u64;

        Ok(Signature { r, s, v })
    }
}

fn convert_signature(resp: &EthereumTxRequest, chain_id: Option<u64>) -> Result<Signature> {
    let mut v = resp.signature_v() as u64;
    if let Some(chain_id) = chain_id {
        if v <= 1 {
            v = v + 2 * chain_id + 35;
        }
    }
    let r = resp.signature_r().try_into().map_err(|_| Error::MalformedSignature)?;
    let s = resp.signature_s().try_into().map_err(|_| Error::MalformedSignature)?;
    Ok(Signature { r, s, v })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;

    #[test]
    fn test_serialize() {
        let chain_id: U256 = "1".parse().unwrap();
        let chain_id_v = serde_json::to_value(chain_id).unwrap();
        let bytes = encode_data(chain_id_v, "uint256").unwrap();
        println!("{bytes:?}",);
    }
}
