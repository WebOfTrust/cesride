use hex_literal::hex;
use wasm_bindgen_test::*;

use cesride_core::matter::Codex;

use cesride_wasm::BexterWrapper;
use cesride_wasm::CesrideMatterCodex;
use cesride_wasm::CigarWrapper;
use cesride_wasm::DaterWrapper;
use cesride_wasm::SaiderWrapper;
use cesride_wasm::SerderWrapper;
use cesride_wasm::VerferWrapper;
use cesride_wasm::ValueWrapper;

/* 
These dater tests are transcriptions from the first two test_dater tests in
test_coring from keripy.
*/
#[wasm_bindgen_test]
fn test_dater_default_now() {
	// Default constructor should be equivalent to something like now()
	// We just check the structure of this one.
    let dater = DaterWrapper::new(None, None, None, None, None, None).unwrap();
	assert_eq!(dater.code(), CesrideMatterCodex::DateTime.code());
	assert_eq!(dater.raw().len(), 24);
	assert_eq!(dater.qb64().unwrap().len(), 36);
	assert_eq!(dater.qb2().unwrap().len(), 27);
	assert_eq!(dater.dts().unwrap().len(), 32); 
}

#[wasm_bindgen_test]
fn test_dater_dts1_construction() {
    let dts1 = "2020-08-22T17:50:09.988921+00:00";
    let dts1b = b"2020-08-22T17:50:09.988921+00:00";
    let dt1raw = b"\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdbZt\xd1\xcd4";
    let dt1qb64 = "1AAG2020-08-22T17c50c09d988921p00c00";
    let dt1qb64b = b"1AAG2020-08-22T17c50c09d988921p00c00";
    let dt1qb2 = b"\xd4\x00\x06\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdbZt\xd1\xcd4";

    let dater = DaterWrapper::new(Some(dts1.to_string()), None, None, None, None, None).unwrap();
    assert_eq!(dater.raw(), b"\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdbZt\xd1\xcd4");
    assert_eq!(dater.code(), CesrideMatterCodex::DateTime.code());
    assert_eq!(dater.dts().unwrap(), dts1);
    assert_eq!(dater.dtsb().unwrap(), dts1b);
    assert_eq!(dater.raw(), dt1raw);
    assert_eq!(dater.qb64().unwrap(), dt1qb64);
    assert_eq!(dater.qb64b().unwrap(), dt1qb64b);
    assert_eq!(dater.qb2().unwrap(), dt1qb2);
}

#[wasm_bindgen_test]
fn test_bexter_bext_string_simple_arg() {
    let first_bexter = BexterWrapper::new(Some("A".to_string()), None, None, None, None, None).unwrap();
    let second_bexter = BexterWrapper::new(Some("A".to_string()), None, None, None, None, None).unwrap();
    assert_eq!(first_bexter.bext(), second_bexter.bext());
    assert_eq!(first_bexter.code(), second_bexter.code());
    assert_eq!(first_bexter.size(), second_bexter.size());
    assert_eq!(first_bexter.raw(), second_bexter.raw());
    assert_eq!(first_bexter.qb64(), second_bexter.qb64());
    assert_eq!(first_bexter.qb64b(), second_bexter.qb64b());
    assert_eq!(first_bexter.qb2(), second_bexter.qb2());
}

#[wasm_bindgen_test]
fn test_cigar_convenience() {
    let verf_default = VerferWrapper::default();
    let code = Codex::Ed25519_Sig;
    let raw = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ[]";

    let first_cigar = CigarWrapper::new(Some(verf_default.clone()), Some(code.to_string()), Some(raw.to_vec()), None, None, None).unwrap();
    let second_cigar = CigarWrapper::new(Some(verf_default), Some(code.to_string()), Some(raw.to_vec()), None, None, None).unwrap();
    assert_eq!(first_cigar.verfer(), second_cigar.verfer());
    assert_eq!(first_cigar.code(), second_cigar.code());
    assert_eq!(first_cigar.size(), second_cigar.size());
    assert_eq!(first_cigar.raw(), second_cigar.raw());
    assert_eq!(first_cigar.qb64(), second_cigar.qb64());
    assert_eq!(first_cigar.qb64b(), second_cigar.qb64b());
    assert_eq!(first_cigar.qb2(), second_cigar.qb2());
}

#[wasm_bindgen_test]
fn test_verfer_convenience() {
    let raw = &hex!("0123456789abcdef00001111222233334444555566667777888899990000aaaa");
    let code = Codex::Ed25519N;
    let verf_wrapper = VerferWrapper::new(Some(code.to_string()), Some(raw.to_vec()), None, None, None).unwrap();
    let verf_wrapper_2 = verf_wrapper.clone();
    assert_eq!(verf_wrapper.code(), verf_wrapper_2.code());
    assert_eq!(verf_wrapper.size(), verf_wrapper_2.size());
    assert_eq!(verf_wrapper.raw(), verf_wrapper_2.raw());
    assert_eq!(verf_wrapper.qb64(), verf_wrapper_2.qb64());
    assert_eq!(verf_wrapper.qb64b(), verf_wrapper_2.qb64b());
    assert_eq!(verf_wrapper.qb2(), verf_wrapper_2.qb2());
}

#[wasm_bindgen_test]
fn test_serder_convenience() {
    let e1 = r#"{
        "v": "KERI10JSON000000_",
        "d": "",
        "i": "ABCDEFG",
        "s": "0001",
        "t": "rot"
    }"#;
    let saidify_returned = SaiderWrapper::saidify(ValueWrapper::new(&e1), None, None, None, None).unwrap();
    let e1 = saidify_returned.value();

    let serder = SerderWrapper::new(None, None, None, Some(ValueWrapper::new(e1.as_str())), None).unwrap();
    let serder2 = SerderWrapper::new(None, Some(serder.raw()), None, None, None).unwrap();

    assert_eq!(serder.pre().unwrap(), serder2.pre().unwrap());
}

#[wasm_bindgen_test]
fn test_saider_convenience() {
    let sad = r#"{"d":""}"#;
    let wrapper = SaiderWrapper::new(Some(ValueWrapper::new(&sad)),
        None, None, None, None, None, None, None, None).unwrap();
    assert_eq!(wrapper.code(), wrapper.code());
}
