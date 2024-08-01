use bitcoin::opcodes::all::{OP_NOP5, OP_PUSHBYTES_1, OP_RETURN};
use bitcoin::opcodes::OP_TRUE;
use bitcoin::{opcodes::All, Script, ScriptBuf, TxOut};
use byteorder::{ByteOrder, BigEndian};
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

    pub fn op_drivechain(mut self, sidechain_number: u8) -> Self {
        let message = CoinbaseMessage::OpDrivechain { sidechain_number };
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
    OpDrivechain {
        sidechain_number: u8,
    },
}

const M1_PROPOSE_SIDECHAIN_TAG: &[u8] = &[0xD5, 0xE0, 0xC4, 0xAF];
const M2_ACK_SIDECHAIN_TAG: &[u8] = &[0xD6, 0xE1, 0xC5, 0xDF];
const M3_PROPOSE_BUNDLE_TAG: &[u8] = &[0xD4, 0x5A, 0xA9, 0x43];
const M4_ACK_BUNDLES_TAG: &[u8] = &[0xD7, 0x7D, 0x17, 0x76];

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
    if let Ok((input, sidechain_number)) = parse_op_drivechain(script) {
        return Ok((input, CoinbaseMessage::OpDrivechain { sidechain_number }));
    }
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

impl Into<ScriptBuf> for CoinbaseMessage {
    fn into(self) -> ScriptBuf {
        match self {
            Self::OpDrivechain { sidechain_number } => {
                let message = [
                    OP_DRIVECHAIN.to_u8(),
                    OP_PUSHBYTES_1.to_u8(),
                    sidechain_number,
                    OP_TRUE.to_u8(),
                ];
                let script_pubkey = ScriptBuf::from_bytes(message.into());
                dbg!(&script_pubkey);
                return script_pubkey;
            }
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
