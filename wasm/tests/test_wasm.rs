use wasm_bindgen_test::*;

use cesride_wasm::BexterWrapper;
use cesride_wasm::DaterWrapper;
use cesride_wasm::CesrideMatterCodex;

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
