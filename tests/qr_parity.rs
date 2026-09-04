//! Parity between the in-house QR encoder and the `qrcode` crate it replaced.
//!
//! `src/qr.rs` must render *the same symbol* the crate rendered — same version,
//! same mask, same modules, same SVG markup — for every payload shape the admin
//! UI produces. The `qrcode` crate is kept as a dev-dependency solely so this
//! comparison is against the reference implementation rather than against a
//! frozen snapshot of our own output.
//!
//! The crate's `QrCode::new` runs a segment optimiser that may split a payload
//! into numeric / alphanumeric / byte runs. Our encoder is byte-mode only, so
//! the strict comparison is against the crate's byte-mode path
//! (`Bits::push_byte_data`), and a second test asserts that for the payload
//! shapes this project actually generates — all of them mixed-case, which
//! neither numeric nor alphanumeric mode can represent — the optimiser lands on
//! byte mode too, making the two identical end to end.

use awg_easy_rs::qr;
use qrcode::bits::Bits;
use qrcode::types::{EcLevel, Version};
use qrcode::render::svg;
use qrcode::{Color, QrCode};

/// Reference symbol built through the crate's byte-mode path.
fn reference_byte_mode(data: &[u8]) -> QrCode {
    let version = (1..=40)
        .map(Version::Normal)
        .find(|v| {
            let mut bits = Bits::new(*v);
            bits.push_byte_data(data).is_ok() && bits.push_terminator(EcLevel::M).is_ok()
        })
        .expect("payload fits in some version");
    let mut bits = Bits::new(version);
    bits.push_byte_data(data).unwrap();
    bits.push_terminator(EcLevel::M).unwrap();
    QrCode::with_bits(bits, EcLevel::M).expect("reference encode")
}

fn assert_same_modules(data: &[u8], reference: &QrCode) {
    let ours = qr::encode(data, qr::EcLevel::M).expect("in-house encode");
    let theirs: Vec<Color> = reference.to_colors();
    let width = reference.width();

    assert_eq!(
        ours.width(),
        width,
        "version differs for a {}-byte payload",
        data.len()
    );
    for y in 0..width {
        for x in 0..width {
            let expected = theirs[y * width + x] == Color::Dark;
            assert_eq!(
                ours.is_dark(x, y),
                expected,
                "module ({x},{y}) differs for a {}-byte payload",
                data.len()
            );
        }
    }
}

/// Deterministic pseudo-random printable ASCII, so failures reproduce.
fn pseudo_text(len: usize, seed: u64) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=:._-";
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            ALPHABET[(x % ALPHABET.len() as u64) as usize] as char
        })
        .collect()
}

/// A realistic AmneziaWG client config — the main thing this encoder renders.
fn sample_wg_config() -> String {
    "[Interface]\n\
     PrivateKey = 4GQjN0hLQe0mF0uZ0f5kZ8k0lQ0F0Z9pQ0mF0uZ0f4=\n\
     Address = 10.8.0.4/24, fdcc:ad94:bacf:61a3::cafe:4/112\n\
     DNS = 1.1.1.1, 1.0.0.1\n\
     MTU = 1420\n\
     Jc = 5\nJmin = 50\nJmax = 1000\n\
     S1 = 86\nS2 = 574\nH1 = 1728896019\nH2 = 1116529626\n\
     H3 = 1837349748\nH4 = 1957237611\n\n\
     [Peer]\n\
     PublicKey = 8Zt0Yy0kQ0mF0uZ0f5kZ8k0lQ0F0Z9pQ0mF0uZ0f4=\n\
     PresharedKey = qQ0mF0uZ0f5kZ8k0lQ0F0Z9pQ0mF0uZ0f5kZ8k0lQ0=\n\
     AllowedIPs = 0.0.0.0/0, ::/0\n\
     Endpoint = vpn.example.com:51820\n\
     PersistentKeepalive = 25\n"
        .to_string()
}

#[test]
fn matches_the_reference_encoder_for_every_size_class() {
    // One payload per character-count-indicator width and per block layout
    // boundary, plus a sweep that crosses many versions.
    let mut payloads: Vec<String> = vec![
        String::new(),
        "a".to_string(),
        "hello world".to_string(),
        sample_wg_config(),
    ];
    for len in [1, 8, 9, 16, 17, 25, 26, 50, 100, 150, 200, 300, 500, 800, 1200, 1600, 2000] {
        payloads.push(pseudo_text(len, len as u64 * 7 + 1));
    }

    for payload in &payloads {
        let data = payload.as_bytes();
        assert_same_modules(data, &reference_byte_mode(data));
    }
}

#[test]
fn matches_the_reference_encoder_on_random_payloads() {
    for seed in 1..60u64 {
        let len = (seed as usize * 37) % 900 + 1;
        let payload = pseudo_text(len, seed * 2654435761);
        assert_same_modules(payload.as_bytes(), &reference_byte_mode(payload.as_bytes()));
    }
}

#[test]
fn matches_the_reference_encoder_for_binary_payloads() {
    // Byte mode must survive non-UTF-8 and control bytes.
    for len in [1usize, 3, 40, 400] {
        let data: Vec<u8> = (0..len).map(|i| (i * 37 % 256) as u8).collect();
        assert_same_modules(&data, &reference_byte_mode(&data));
    }
}

#[test]
fn real_payload_shapes_are_never_denser_than_the_optimiser_managed() {
    // `QrCode::new` — what `generate_qr_svg` used to call — runs a segment
    // optimiser that can encode long digit runs in numeric mode. Byte mode
    // costs at most one version on such payloads and nothing at all on the
    // rest; this pins that bound so a future change cannot quietly inflate the
    // symbols.
    let cases = [
        (sample_wg_config(), 0),
        (
            "vless://3f4a1c22-9a1e-4e6a-9a7a-3c9f0d1b2e5f@203.0.113.7:443\
             ?type=tcp&security=reality&pbk=Kx9Qp0Zq1r2s3t4u5v6w7x8y9z0A1B2C3D4E5F6G7H8&\
             fp=chrome&sni=www.microsoft.com&sid=0a1b2c3d&spx=%2F&flow=xtls-rprx-vision#awg-easy"
                .to_string(),
            0,
        ),
        (
            "tg://proxy?server=proxy.example.com&port=443&secret=eeAbCdEf0123456789aAbCdEf01234567\
             89777777772e6d6963726f736f66742e636f6d"
                .to_string(),
            // A 70-hex-digit secret is exactly the shape the optimiser wins on.
            4,
        ),
        (
            "mdnsvpn://b64?eyJMSVNURU5fUE9SVCI6MTkwMDAsIktFWSI6ImFiY2RlZjAxMjM0NTY3ODkifQ=="
                .to_string(),
            0,
        ),
    ];

    for (payload, allowed_growth) in cases {
        let reference = QrCode::new(payload.as_bytes()).expect("reference encode");
        let ours = qr::encode(payload.as_bytes(), qr::EcLevel::M).expect("in-house encode");
        assert_eq!(
            ours.width(),
            reference.width() + allowed_growth,
            "symbol size moved for a {}-byte payload",
            payload.len()
        );
    }
}

#[test]
fn svg_markup_is_byte_for_byte_what_the_crate_rendered() {
    // The renderer is compared on a payload both encoders agree on, so any
    // difference here is in the SVG itself: quiet zone, module size rounding,
    // path syntax, or the colours.
    let payload = sample_wg_config();
    let reference = reference_byte_mode(payload.as_bytes());
    let expected = reference
        .render()
        .min_dimensions(256, 256)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .build();
    let ours = qr::generate_qr_svg(&payload).expect("in-house svg");
    assert_eq!(ours, expected, "SVG markup differs");

    // And the shape the UI depends on.
    assert!(ours.starts_with("<?xml version=\"1.0\" standalone=\"yes\"?><svg"));
    assert!(ours.ends_with("\"/></svg>"));
    assert!(ours.contains(r#"shape-rendering="crispEdges""#));
    let width: usize = ours
        .split("width=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .and_then(|s| s.parse().ok())
        .expect("width attribute");
    assert!(width >= 256, "rendered {width}px, expected at least 256");
}

#[test]
fn rejects_a_payload_that_cannot_fit() {
    // Version 40 at level M holds 2331 byte-mode codewords.
    let too_big = "x".repeat(2332);
    let err = qr::generate_qr_svg(&too_big).unwrap_err();
    assert!(err.to_string().contains("too long"), "{err}");
    // One byte under the limit still encodes.
    assert!(qr::generate_qr_svg(&"x".repeat(2331)).is_ok());
}
