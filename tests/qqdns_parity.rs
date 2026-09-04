//! Wire-parity tests for the QQ-Tunnel port.
//!
//! Replays `tests/qqdns_vectors.json` — produced directly from the upstream
//! Python (`genvec.py`) — to prove the Rust codec, DNS handling, and
//! reassembler are byte-identical to the reference implementation this
//! interoperates with.

use std::time::Duration;

use awg_easy_rs::qqdns::codec::{
    self, get_base32_final_domains, get_chunk_data, get_chunk_len, SendDomain, DATA_OFFSET_WIDTH,
    TOTAL_DATA_OFFSET,
};
use awg_easy_rs::qqdns::dns::{
    build_dns_query, create_noerror_empty_response, encode_qname, handle_dns_request, label_domain,
    match_recv_suffix,
};
use awg_easy_rs::qqdns::reassembly::DataHandler;
use serde_json::Value;

fn vectors() -> Value {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/qqdns_vectors.json"
    ))
    .expect("vectors file present");
    serde_json::from_str(&raw).expect("valid json")
}

fn hexd(s: &str) -> Vec<u8> {
    awg_easy_rs::encoding::hex_decode(s).expect("valid hex")
}

#[test]
fn base32_roundtrip_parity() {
    let v = vectors();
    for e in v["b32"].as_array().unwrap() {
        let raw = hexd(e["raw"].as_str().unwrap());
        let enc = codec::b32_encode_nopad_lower(&raw);
        assert_eq!(
            enc,
            e["enc"].as_str().unwrap().as_bytes(),
            "encode {:?}",
            e
        );
        let dec = codec::b32_decode_nopad(e["enc"].as_str().unwrap().as_bytes()).unwrap();
        assert_eq!(dec, hexd(e["dec"].as_str().unwrap()), "decode {:?}", e);
    }
}

#[test]
fn number_base32_parity() {
    let v = vectors();
    for e in v["num"].as_array().unwrap() {
        let n = e["n"].as_u64().unwrap() as u32;
        let w = e["w"].as_u64().unwrap() as usize;
        let enc = codec::number_to_base32_lower(n, w);
        assert_eq!(enc, e["enc"].as_str().unwrap().as_bytes(), "num {:?}", e);
        let back = codec::base32_to_number(&enc).unwrap();
        assert_eq!(back as u64, e["back"].as_u64().unwrap(), "back {:?}", e);
    }
}

#[test]
fn chunk_len_parity() {
    let v = vectors();
    for e in v["chunk_len"].as_array().unwrap() {
        let medl = e["max_encoded_domain_len"].as_i64().unwrap();
        let qlen = e["qname_encoded_len"].as_i64().unwrap();
        let msl = e["max_sub_len"].as_i64().unwrap();
        let dow = e["data_offset_width"].as_i64().unwrap();
        assert_eq!(
            codec::compute_max_m(msl, medl - qlen),
            e["max_m"].as_i64().unwrap(),
            "max_m {:?}",
            e
        );
        assert_eq!(
            get_chunk_len(medl, qlen, msl, dow).unwrap() as i64,
            e["chunk_len"].as_i64().unwrap(),
            "chunk_len {:?}",
            e
        );
    }
}

#[test]
fn encode_qname_parity() {
    let v = vectors();
    for e in v["qname"].as_array().unwrap() {
        let d = e["domain"].as_str().unwrap().as_bytes();
        assert_eq!(
            encode_qname(d),
            hexd(e["encode_qname"].as_str().unwrap()),
            "encode_qname {:?}",
            e
        );
        let labels: Vec<String> = label_domain(d)
            .iter()
            .map(|l| String::from_utf8(l.clone()).unwrap())
            .collect();
        let want: Vec<String> = e["label_domain"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect();
        assert_eq!(labels, want, "label_domain {:?}", e);
    }
}

#[test]
fn final_domains_parity() {
    let v = vectors();
    for e in v["final_domains"].as_array().unwrap() {
        let payload = hexd(e["payload"].as_str().unwrap());
        let data_offset = e["data_offset"].as_u64().unwrap() as u32;
        let send_domain = e["send_domain"].as_str().unwrap().as_bytes();
        let qenc = encode_qname(send_domain);
        let chunk_len = get_chunk_len(255, qenc.len() as i64, 63, DATA_OFFSET_WIDTH as i64).unwrap();
        assert_eq!(chunk_len, e["chunk_len"].as_u64().unwrap() as usize);

        let sd = vec![SendDomain {
            qname_encoded: qenc,
            chunk_len,
        }];
        let domains = get_base32_final_domains(
            &payload,
            data_offset,
            0,
            &sd,
            63,
            DATA_OFFSET_WIDTH,
            255,
        );
        let want: Vec<Vec<u8>> = e["domains"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| hexd(x.as_str().unwrap()))
            .collect();
        assert_eq!(domains, want, "final_domains {:?}", e["payload"]);
        assert_eq!(domains.len(), e["num_domains"].as_u64().unwrap() as usize);
    }
}

#[test]
fn chunk_data_parity() {
    let v = vectors();
    let recv = vec![label_domain(b"nb.example.com")];
    for e in v["chunk_data"].as_array().unwrap() {
        let wire = hexd(e["wire"].as_str().unwrap());
        // Full receive path: build a query around the QNAME, parse, strip suffix.
        let q = build_dns_query(&wire, 0x1234, 1);
        let parsed = handle_dns_request(&q).unwrap();
        let suffix = match_recv_suffix(&parsed.labels, &recv).unwrap();
        let data_with_header: Vec<u8> = parsed.labels[..parsed.labels.len() - suffix]
            .iter()
            .flatten()
            .copied()
            .collect();
        let cd = get_chunk_data(&data_with_header, DATA_OFFSET_WIDTH).unwrap();
        assert_eq!(cd.data_offset, e["data_offset"].as_u64().unwrap() as u32);
        assert_eq!(
            cd.fragment_part,
            e["fragment_part"].as_u64().unwrap() as usize
        );
        assert_eq!(cd.last_fragment, e["last_fragment"].as_bool().unwrap());
        assert_eq!(cd.chunk, e["chunk_data"].as_str().unwrap().as_bytes());
    }
}

#[test]
fn dns_message_parity() {
    let v = vectors();
    for e in v["dns"].as_array().unwrap() {
        let qname = encode_qname(e["qname"].as_str().unwrap().as_bytes());
        let q = build_dns_query(&qname, e["qid"].as_u64().unwrap() as u16, 1);
        assert_eq!(q, hexd(e["query_hex"].as_str().unwrap()), "query {:?}", e);
        let parsed = handle_dns_request(&q).unwrap();
        assert_eq!(parsed.qid, e["qid"].as_u64().unwrap() as u16);
        assert_eq!(parsed.qflags, e["qflags"].as_u64().unwrap() as u16);
        assert_eq!(parsed.qtype, e["qtype"].as_u64().unwrap() as u16);
        assert_eq!(
            parsed.next_question,
            e["next_question"].as_u64().unwrap() as usize
        );
        let resp = create_noerror_empty_response(
            parsed.qid,
            parsed.qflags,
            &q[12..parsed.next_question],
        );
        assert_eq!(
            resp,
            hexd(e["response_hex"].as_str().unwrap()),
            "response {:?}",
            e
        );
    }
}

#[test]
fn full_roundtrip_parity() {
    let v = vectors();
    let send_domain = b"nb.example.com";
    let qenc = encode_qname(send_domain);
    let chunk_len = get_chunk_len(255, qenc.len() as i64, 63, DATA_OFFSET_WIDTH as i64).unwrap();
    let sd = vec![SendDomain {
        qname_encoded: qenc,
        chunk_len,
    }];
    let recv = vec![label_domain(send_domain)];

    for e in v["roundtrip"].as_array().unwrap() {
        let payload = hexd(e["payload"].as_str().unwrap());
        let offset = e["offset"].as_u64().unwrap() as u32;
        let domains = get_base32_final_domains(&payload, offset, 0, &sd, 63, DATA_OFFSET_WIDTH, 255);

        let dh = DataHandler::new(TOTAL_DATA_OFFSET as usize, Duration::from_secs(13));
        let mut reassembled: Option<Vec<u8>> = None;
        for d in &domains {
            let q = build_dns_query(d, 1, 1);
            let parsed = handle_dns_request(&q).unwrap();
            let suffix = match_recv_suffix(&parsed.labels, &recv).unwrap();
            let dwh: Vec<u8> = parsed.labels[..parsed.labels.len() - suffix]
                .iter()
                .flatten()
                .copied()
                .collect();
            let cd = get_chunk_data(&dwh, DATA_OFFSET_WIDTH).unwrap();
            if let Some(joined) =
                dh.new_data_event(cd.data_offset, cd.fragment_part, cd.last_fragment, cd.chunk)
            {
                reassembled = Some(codec::b32_decode_nopad(&joined).unwrap());
            }
        }
        assert_eq!(
            reassembled.as_deref(),
            Some(payload.as_slice()),
            "roundtrip {:?}",
            e["payload"]
        );
        assert!(e["ok"].as_bool().unwrap());
    }
}
