//! Emit the checked OpenAPI document.

fn main() {
    print!("{}", openkms::openapi::spec_json_pretty());
}
