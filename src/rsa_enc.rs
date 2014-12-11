extern crate crap_rsa;
extern crate docopt;
extern crate serialize;
extern crate gmp;

use std::io::{File, BufferedReader};

const USAGE: &'static str = "Usage: rsa_env <command> <keyfile> <bits>";

#[deriving(Decodable, Show)]
struct Args {
    arg_command: String,
    arg_keyfile: String,
    arg_bits: u64,
}

fn main() {
    let args: Args = docopt::Docopt::new(USAGE)
        .and_then(|d| d.decode())
        .unwrap_or_else(|e| e.exit());

    match args.arg_command.as_slice() {
        "encrypt" => {
            let mut contents = BufferedReader::new(File::open(&Path::new(args.arg_keyfile)).unwrap());
            let contents = contents.lines().map(|l| l.unwrap()).collect::<Vec<String>>();
            let mut contents = contents.into_iter();
            let e = from_str(contents.next().unwrap().as_slice().trim()).unwrap();
            let n = from_str(contents.next().unwrap().as_slice().trim()).unwrap();
            let key = crap_rsa::PublicKey {
                e: e,
                n: n
            };

            for c in std::io::stdin().lock().chars() {
                let c = c.unwrap();
                println!("{}", crap_rsa::encrypt(&key, &FromPrimitive::from_u32(c as u32).unwrap()));
            }
        },
        "decrypt" => {
            let mut contents = BufferedReader::new(File::open(&Path::new(args.arg_keyfile)).unwrap());
            let contents = contents.lines().map(|l| l.unwrap()).collect::<Vec<String>>();
            let mut contents = contents.into_iter();

            let d = from_str(contents.next().unwrap().as_slice()).unwrap();
            let n = from_str(contents.next().unwrap().as_slice()).unwrap();

            let key = crap_rsa::PrivateKey {
                d: d,
                n: n
            };

            for line in std::io::stdin().lock().lines() {
                let line = line.unwrap();
                let line = from_str(line.as_slice().trim()).unwrap();
                let dec = crap_rsa::decrypt(&key, &line);
                print!("{}", std::char::from_u32(dec.to_u32().unwrap()).unwrap());
            }
        },
        "gen-keys" => {
            let keypair = crap_rsa::KeyPair::generate(args.arg_bits);
            let mut privfile = File::create(&Path::new(format!("{}.priv", args.arg_keyfile)));
            let mut pubfile = File::create(&Path::new(format!("{}.pub", args.arg_keyfile)));
            (writeln!(&mut privfile, "{}\n{}", keypair.private.d, keypair.private.n)).unwrap();
            (writeln!(&mut pubfile, "{}\n{}", keypair.public.e, keypair.public.n)).unwrap();
            println!("Keys generated!");
        },
        _ => { println!("Unknown command"); std::os::set_exit_status(1); return }
    }
}
