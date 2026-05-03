const COMMITTED_OPENAPI: &str = include_str!("../openapi/openkms.v1.json");

#[test]
fn committed_openapi_matches_generator() {
    let generated = openkms::openapi::spec_json_pretty();
    assert_eq!(
        COMMITTED_OPENAPI, generated,
        "openapi/openkms.v1.json is stale; regenerate with `cargo run --bin generate_openapi > openapi/openkms.v1.json`"
    );
}
