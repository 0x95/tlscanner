use std::{
    env,
    io::{self, IsTerminal, Read},
};

use crate::scanner::scan::TlsScan;

mod scanner;

fn scan(host: &str) {
    println!("{}", TlsScan::new(host).run().unwrap());
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let stdin = io::stdin();
    openssl::init();

    let has_pipe = !stdin.is_terminal();

    if has_pipe {
        let mut buffer = String::new();
        io::stdin()
            .read_to_string(&mut buffer)
            .expect("Failed to read from stdin");
        buffer.trim().to_string().lines().for_each(scan);
    } else if !args.is_empty() {
        scan(args.first().unwrap());
    } else {
        let program_name = env::args().next().unwrap_or_else(|| "program".to_string());
        eprintln!(
            "Usage: {} <input>  OR  echo 'input' | {}",
            program_name, program_name
        );
        std::process::exit(1);
    };
}
