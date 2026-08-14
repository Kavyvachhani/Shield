//! Scores CVSS 4.0 vectors read from stdin, one per line, printing
//! `vector<TAB>score`.
//!
//! Exists so the calculator can be differentially tested against the reference
//! implementation published by FIRST.ORG and Red Hat: agreement across the whole
//! base-metric space is the only convincing evidence that a reimplementation of
//! this algorithm is correct.

use sentinel_core::scoring::Cvss4Vector;
use std::io::{self, BufRead, BufWriter, Write};

fn main() {
    let stdin = io::stdin();
    let mut out = BufWriter::new(io::stdout().lock());

    for line in stdin.lock().lines() {
        let line = line.expect("read stdin");
        let vector = line.trim();
        if vector.is_empty() {
            continue;
        }
        match Cvss4Vector::parse(vector) {
            Ok(v) => writeln!(out, "{vector}\t{:.1}", v.score()).unwrap(),
            Err(e) => writeln!(out, "{vector}\tERROR: {e}").unwrap(),
        }
    }
}
