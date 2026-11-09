use std::io::{self, Read};
use sovereign_sealer::{handle, SealRequest};

fn main() {
    let mut input = String::new();
    if io::stdin().take(2 * 1024 * 1024).read_to_string(&mut input).is_err() {
        println!(r#"{{"status":"error","error":"input_read_failed"}}"#); std::process::exit(2);
    }
    let request: SealRequest = match serde_json::from_str(&input) {
        Ok(v) => v,
        Err(_) => { println!(r#"{{"status":"error","error":"invalid_request_json"}}"#); std::process::exit(2); }
    };
    let response = handle(request);
    let failed = response.status != "success";
    println!("{}", serde_json::to_string(&response).unwrap_or_else(|_| r#"{"status":"error","error":"serialization_failed"}"#.into()));
    if failed { std::process::exit(1); }
}
