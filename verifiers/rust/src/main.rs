//! AlgoVoi substrate-pqc — Rust producer and verifier.
//!
//! Dispatches on argv[1]:
//!   produce <output_path>   — signs the canonical payload, writes artefact JSON
//!   verify  <artefact_path> — reads artefact, verifies all schemes, exits 0 iff all pass

use std::{env, process};

mod produce;
mod verify;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: {} produce <output_path>", args[0]);
        eprintln!("       {} verify  <artefact_path>", args[0]);
        process::exit(2);
    }
    match args[1].as_str() {
        "produce" => produce::run(&args[2]),
        "verify" => verify::run(&args[2]),
        other => {
            eprintln!("unknown command: {}", other);
            process::exit(2);
        }
    }
}
