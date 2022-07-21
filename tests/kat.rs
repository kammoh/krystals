use std::fs::File;
use std::io::{self, BufRead, BufReader, Lines};
use std::path::Path;

fn decode_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("Hex string decoding"))
        .collect::<Vec<u8>>()
}

#[derive(Debug)]
pub struct KAT {
    pub keygen_rand0: Vec<u8>,
    pub keygen_rand1: Vec<u8>,
    pub encap_rand: Vec<u8>,
    pub pk: Vec<u8>,
    pub sk: Vec<u8>,
    pub ct: Vec<u8>,
    pub ss: Vec<u8>,
}

// Converts string octuples from tvec files into Kat structs
impl From<&[String]> for KAT {
    fn from(kat: &[String]) -> Self {
        // Extract values from key:value lines
        let values: Vec<String> = kat
            .iter()
            .map(|katline| {
                let val: Vec<&str> = katline.split(": ").collect();
                if val.len() > 1 {
                    val[1].into()
                } else {
                    val[0].into()
                }
            })
            .collect();
        // Build KAT from values
        KAT {
            keygen_rand0: decode_hex(&values[0]),
            keygen_rand1: decode_hex(&values[1]),
            pk: decode_hex(&values[2]),
            sk: decode_hex(&values[3]),
            encap_rand: decode_hex(&values[4]),
            ct: decode_hex(&values[5]),
            ss: decode_hex(&values[6]),
        }
    }
}

pub fn kyber_k_to_security(kyber_k: usize) -> usize {
    match kyber_k {
        2 => 512,
        3 => 768,
        4 => 1024,
        _ => panic!("Unknown Kyber K"),
    }
}

pub struct KatFile {
    pub lines: Lines<BufReader<File>>,
}

impl Iterator for KatFile {
    type Item = KAT;

    fn next(&mut self) -> Option<Self::Item> {
        let mut v = vec![String::default(); 8];
        for i in 0..8 {
            match self.lines.next() {
                Some(Ok(line)) => v[i] = line,
                _ => return None,
            }
        }
        Some(KAT::from(v.as_slice()))
    }
}

impl KatFile {
    pub fn new(path: &Path) -> io::Result<KatFile> {
        File::open(path).and_then(|f| {
            Ok(KatFile {
                lines: BufReader::new(f).lines(),
            })
        })
    }
}
