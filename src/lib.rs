use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::{OP_NOP5, OP_PUSHBYTES_1, OP_RETURN};
use bitcoin::opcodes::OP_TRUE;
use bitcoin::Transaction;
use bitcoin::{opcodes::All, Script, ScriptBuf, TxOut};
use byteorder::{BigEndian, ByteOrder};
use nom::branch::alt;
use nom::bytes::complete::{tag, take};
use nom::combinator::fail;
use nom::combinator::rest;
use nom::multi::many0;
use nom::IResult;
use sha2::{Digest, Sha256};

pub use bitcoin;

pub const OP_DRIVECHAIN: All = OP_NOP5;

pub struct CoinbaseBuilder {
    messages: Vec<CoinbaseMessage>,
}

impl CoinbaseBuilder {
    pub fn new() -> Self {
        CoinbaseBuilder { messages: vec![] }
    }

    pub fn build(self) -> Vec<TxOut> {
        self.messages
            .into_iter()
            .map(|message| TxOut {
                value: 0,
                script_pubkey: message.into(),
            })
            .collect()
    }

    pub fn propose_sidechain(mut self, sidechain_number: u8, data: &[u8]) -> Self {
        let message = CoinbaseMessage::M1ProposeSidechain {
            sidechain_number,
            data: data.to_vec(),
        };
        self.messages.push(message);
        self
    }

    pub fn ack_sidechain(mut self, sidechain_number: u8, data_hash: &[u8; 32]) -> Self {
        let message = CoinbaseMessage::M2AckSidechain {
            sidechain_number,
            data_hash: data_hash.clone(),
        };
        self.messages.push(message);
        self
    }

    pub fn propose_bundle(mut self, sidechain_number: u8, bundle_hash: &[u8; 32]) -> Self {
        let message = CoinbaseMessage::M3ProposeBundle {
            sidechain_number,
            bundle_txid: bundle_hash.clone(),
        };
        self.messages.push(message);
        self
    }

    pub fn ack_bundles(mut self, m4_ack_bundles: M4AckBundles) -> Self {
        let message = CoinbaseMessage::M4AckBundles(m4_ack_bundles);
        self.messages.push(message);
        self
    }

    pub fn bmm_accept(mut self, sidechain_number: u8, bmm_hash: &[u8; 32]) -> Self {
        let message = CoinbaseMessage::M7BmmAccept {
            sidechain_number,
            sidechain_block_hash: *bmm_hash,
        };
        self.messages.push(message);
        self
    }
}

#[derive(Debug)]
pub enum CoinbaseMessage {
    M1ProposeSidechain {
        sidechain_number: u8,
        data: Vec<u8>,
    },
    M2AckSidechain {
        sidechain_number: u8,
        data_hash: [u8; 32],
    },
    M3ProposeBundle {
        sidechain_number: u8,
        bundle_txid: [u8; 32],
    },
    M4AckBundles(M4AckBundles),
    M7BmmAccept {
        sidechain_number: u8,
        sidechain_block_hash: [u8; 32],
    },
}

#[derive(Debug)]
pub struct M8BmmRequest {
    pub sidechain_number: u8,
    pub sidechain_block_hash: [u8; 32],
    pub prev_mainchain_block_hash: [u8; 32],
}

const M1_PROPOSE_SIDECHAIN_TAG: &[u8] = &[0xD5, 0xE0, 0xC4, 0xAF];
const M2_ACK_SIDECHAIN_TAG: &[u8] = &[0xD6, 0xE1, 0xC5, 0xDF];
const M3_PROPOSE_BUNDLE_TAG: &[u8] = &[0xD4, 0x5A, 0xA9, 0x43];
const M4_ACK_BUNDLES_TAG: &[u8] = &[0xD7, 0x7D, 0x17, 0x76];
const M7_BMM_ACCEPT_TAG: &[u8] = &[0xD1, 0x61, 0x73, 0x68];
const M8_BMM_REQUEST_TAG: &[u8] = &[0x00, 0xBF, 0x00];

pub const ABSTAIN_ONE_BYTE: u8 = 0xFF;
pub const ABSTAIN_TWO_BYTES: u16 = 0xFFFF;

pub const ALARM_ONE_BYTE: u8 = 0xFE;
pub const ALARM_TWO_BYTES: u16 = 0xFFFE;

#[derive(Debug)]
pub enum M4AckBundles {
    RepeatPrevious,
    OneByte { upvotes: Vec<u8> },
    TwoBytes { upvotes: Vec<u16> },
    LeadingBy50,
}

const REPEAT_PREVIOUS_TAG: &[u8] = &[0x00];
const ONE_BYTE_TAG: &[u8] = &[0x01];
const TWO_BYTES_TAG: &[u8] = &[0x02];
const LEADING_BY_50_TAG: &[u8] = &[0x03];

/// 0xFF
// 0xFFFF
// const ABSTAIN_TAG: &[u8] = &[0xFF];

/// 0xFE
// 0xFFFE
// const ALARM_TAG: &[u8] = &[0xFE];

impl M4AckBundles {
    fn tag(&self) -> u8 {
        match self {
            Self::RepeatPrevious => REPEAT_PREVIOUS_TAG[0],
            Self::OneByte { .. } => ONE_BYTE_TAG[0],
            Self::TwoBytes { .. } => TWO_BYTES_TAG[0],
            Self::LeadingBy50 { .. } => LEADING_BY_50_TAG[0],
        }
    }
}

pub fn parse_coinbase_script<'a>(script: &'a Script) -> IResult<&'a [u8], CoinbaseMessage> {
    let script = script.as_bytes();
    let (input, _) = tag(&[OP_RETURN.to_u8()])(script)?;
    let (input, message_tag) = alt((
        tag(M1_PROPOSE_SIDECHAIN_TAG),
        tag(M2_ACK_SIDECHAIN_TAG),
        tag(M3_PROPOSE_BUNDLE_TAG),
        tag(M4_ACK_BUNDLES_TAG),
    ))(input)?;
    if message_tag == M1_PROPOSE_SIDECHAIN_TAG {
        return parse_m1_propose_sidechain(input);
    } else if message_tag == M2_ACK_SIDECHAIN_TAG {
        return parse_m2_ack_sidechain(input);
    } else if message_tag == M3_PROPOSE_BUNDLE_TAG {
        return parse_m3_propose_bundle(input);
    } else if message_tag == M4_ACK_BUNDLES_TAG {
        return parse_m4_ack_bundles(input);
    } else if message_tag == M7_BMM_ACCEPT_TAG {
        return parse_m7_bmm_accept(input);
    }
    fail(input)
}

pub fn parse_op_drivechain(input: &[u8]) -> IResult<&[u8], u8> {
    let (input, op_drivechain_tag) = tag(&[OP_DRIVECHAIN.to_u8(), OP_PUSHBYTES_1.to_u8()])(input)?;
    dbg!(&op_drivechain_tag);
    let (input, sidechain_number) = take(1usize)(input)?;
    let sidechain_number = sidechain_number[0];
    tag(&[OP_TRUE.to_u8()])(input)?;
    return Ok((input, sidechain_number));
}

fn parse_m1_propose_sidechain(input: &[u8]) -> IResult<&[u8], CoinbaseMessage> {
    let (input, sidechain_number) = take(1usize)(input)?;
    let sidechain_number = sidechain_number[0];
    let (input, data) = rest(input)?;
    let data = data.to_vec();
    let message = CoinbaseMessage::M1ProposeSidechain {
        sidechain_number,
        data,
    };
    return Ok((input, message));
}

fn parse_m2_ack_sidechain(input: &[u8]) -> IResult<&[u8], CoinbaseMessage> {
    let (input, sidechain_number) = take(1usize)(input)?;
    let sidechain_number = sidechain_number[0];
    let (input, data_hash) = take(32usize)(input)?;
    let data_hash: [u8; 32] = data_hash.try_into().unwrap();
    let message = CoinbaseMessage::M2AckSidechain {
        sidechain_number,
        data_hash,
    };
    return Ok((input, message));
}

fn parse_m3_propose_bundle(input: &[u8]) -> IResult<&[u8], CoinbaseMessage> {
    let (input, sidechain_number) = take(1usize)(input)?;
    let sidechain_number = sidechain_number[0];
    let (input, bundle_txid) = take(32usize)(input)?;
    let bundle_txid: [u8; 32] = bundle_txid.try_into().unwrap();
    let message = CoinbaseMessage::M3ProposeBundle {
        sidechain_number,
        bundle_txid,
    };
    return Ok((input, message));
}

fn parse_m4_ack_bundles(input: &[u8]) -> IResult<&[u8], CoinbaseMessage> {
    let (input, m4_tag) = alt((
        tag(REPEAT_PREVIOUS_TAG),
        tag(ONE_BYTE_TAG),
        tag(TWO_BYTES_TAG),
        tag(LEADING_BY_50_TAG),
    ))(input)?;

    if m4_tag == REPEAT_PREVIOUS_TAG {
        let message = CoinbaseMessage::M4AckBundles(M4AckBundles::RepeatPrevious);
        return Ok((input, message));
    } else if m4_tag == ONE_BYTE_TAG {
        let (input, upvotes) = rest(input)?;
        let upvotes = upvotes.to_vec();
        let message = CoinbaseMessage::M4AckBundles(M4AckBundles::OneByte { upvotes });
        return Ok((input, message));
    } else if m4_tag == TWO_BYTES_TAG {
        let (input, upvotes) = many0(take(2usize))(input)?;
        let upvotes: Vec<u16> = upvotes
            .into_iter()
            .map(|upvote| BigEndian::read_u16(upvote))
            .collect();
        let message = CoinbaseMessage::M4AckBundles(M4AckBundles::TwoBytes { upvotes });
        return Ok((input, message));
    } else if m4_tag == LEADING_BY_50_TAG {
        let message = CoinbaseMessage::M4AckBundles(M4AckBundles::LeadingBy50);
        return Ok((input, message));
    }
    return fail(input);
}

fn parse_m7_bmm_accept(input: &[u8]) -> IResult<&[u8], CoinbaseMessage> {
    let (input, sidechain_number) = take(1usize)(input)?;
    let sidechain_number = sidechain_number[0];
    let (input, sidechain_block_hash) = take(32usize)(input)?;
    // Unwrap here is fine, because if we didn't get exactly 32 bytes we'd fail on the previous
    // line.
    let sidechain_block_hash = sidechain_block_hash.try_into().unwrap();
    let message = CoinbaseMessage::M7BmmAccept {
        sidechain_number,
        sidechain_block_hash,
    };
    Ok((input, message))
}

pub fn parse_m8_bmm_request(input: &[u8]) -> IResult<&[u8], M8BmmRequest> {
    let (input, _) = tag(&[OP_RETURN.to_u8()])(input)?;
    let (input, _) = tag(M8_BMM_REQUEST_TAG)(input)?;
    let (input, sidechain_number) = take(1usize)(input)?;
    let sidechain_number = sidechain_number[0];
    let (input, sidechain_block_hash) = take(32usize)(input)?;
    let (input, prev_mainchain_block_hash) = take(32usize)(input)?;
    let sidechain_block_hash = sidechain_block_hash.try_into().unwrap();
    let prev_mainchain_block_hash = prev_mainchain_block_hash.try_into().unwrap();
    let message = M8BmmRequest {
        sidechain_number,
        sidechain_block_hash,
        prev_mainchain_block_hash,
    };
    return Ok((input, message));
}

impl Into<ScriptBuf> for CoinbaseMessage {
    fn into(self) -> ScriptBuf {
        match self {
            Self::M1ProposeSidechain {
                sidechain_number,
                data,
            } => {
                let message = [
                    &[OP_RETURN.to_u8()],
                    M1_PROPOSE_SIDECHAIN_TAG,
                    &[sidechain_number],
                    &data,
                ]
                .concat();
                let script_pubkey = ScriptBuf::from_bytes(message);
                return script_pubkey;
            }
            Self::M2AckSidechain {
                sidechain_number,
                data_hash,
            } => {
                let message = [
                    &[OP_RETURN.to_u8()],
                    M2_ACK_SIDECHAIN_TAG,
                    &[sidechain_number],
                    &data_hash,
                ]
                .concat();
                let script_pubkey = ScriptBuf::from_bytes(message);
                return script_pubkey;
            }
            Self::M3ProposeBundle {
                sidechain_number,
                bundle_txid,
            } => {
                let message = [
                    &[OP_RETURN.to_u8()],
                    M3_PROPOSE_BUNDLE_TAG,
                    &[sidechain_number],
                    &bundle_txid,
                ]
                .concat();
                let script_pubkey = ScriptBuf::from_bytes(message);
                return script_pubkey;
            }
            Self::M4AckBundles(m4_ack_bundles) => {
                let upvotes = match &m4_ack_bundles {
                    M4AckBundles::OneByte { upvotes } => upvotes.clone(),
                    M4AckBundles::TwoBytes { upvotes } => upvotes
                        .iter()
                        .flat_map(|upvote| upvote.to_be_bytes())
                        .collect(),
                    _ => vec![],
                };
                let message = [
                    &[OP_RETURN.to_u8()],
                    M4_ACK_BUNDLES_TAG,
                    &[m4_ack_bundles.tag()],
                    &upvotes,
                ]
                .concat();
                let script_pubkey = ScriptBuf::from_bytes(message);
                return script_pubkey;
            }
            Self::M7BmmAccept {
                sidechain_number,
                sidechain_block_hash,
            } => {
                let message = [
                    &[OP_RETURN.to_u8()],
                    M7_BMM_ACCEPT_TAG,
                    &[sidechain_number],
                    &sidechain_block_hash,
                ]
                .concat();
                let script_pubkey = ScriptBuf::from_bytes(message);
                return script_pubkey;
            }
        }
    }
}

pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let data_sha256_hash: [u8; 32] = hasher.finalize_reset().into();
    hasher.update(data_sha256_hash);
    let data_sha256d_hash: [u8; 32] = hasher.finalize().into();
    data_sha256d_hash
}

pub fn m6_to_id(m6: &Transaction, previous_treasury_utxo_total: u64) -> [u8; 32] {
    let mut m6 = m6.clone();
    /*
    1. Remove the single input spending the previous treasury UTXO from the `vin`
       vector, so that the `vin` vector is empty.
            */
    m6.input.clear();
    /*
    2. Compute `P_total` by summing the `nValue`s of all pay out outputs in this
       `M6`, so `P_total` = sum of `nValue`s of all outputs of this `M6` except for
       the new treasury UTXO at index 0.
            */
    let p_total: u64 = m6.output[1..].iter().map(|o| o.value).sum();
    /*
    3. Set `T_n` equal to the `nValue` of the treasury UTXO created in this `M6`.
        */
    let t_n = m6.output[0].value;
    /*
    4. Compute `F_total = T_n-1 - T_n - P_total`, since we know that `T_n = T_n-1 -
       P_total - F_total`, `T_n-1` was passed as an argument, and `T_n` and
       `P_total` were computed in previous steps..
        */
    let t_n_minus_1 = previous_treasury_utxo_total;
    let f_total = t_n_minus_1 - t_n - p_total;
    /*
    5. Encode `F_total` as `F_total_be_bytes`, an array of 8 bytes encoding the 64
       bit unsigned integer in big endian order.
        */
    let f_total_be_bytes = f_total.to_be_bytes();
    /*
    6. Push an output to the end of `vout` of this `M6` with the `nValue = 0` and
       `scriptPubKey = OP_RETURN F_total_be_bytes`.
        */
    let script_bytes = [vec![OP_RETURN.to_u8()], f_total_be_bytes.to_vec()].concat();
    let script_pubkey = ScriptBuf::from_bytes(script_bytes);
    let txout = TxOut {
        script_pubkey,
        value: 0,
    };
    m6.output.push(txout);
    /*
    At this point we have constructed `M6_blinded`.
        */
    let m6_blinded = m6;
    m6_blinded.txid().to_byte_array()
}
