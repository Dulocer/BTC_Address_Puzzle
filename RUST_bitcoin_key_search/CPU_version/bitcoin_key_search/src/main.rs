use secp256k1::{Secp256k1, SecretKey, PublicKey};
use sha2::{Sha256, Digest};
use ripemd::Ripemd160;
use base58::{ToBase58, FromBase58};
use rand::Rng;
use crossbeam::thread;
use std::fs::File;
use std::io::{Write, stdout};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, Duration};
use lazy_static::lazy_static;
use hex;
use num_cpus;
use ctrlc;

const TARGET_ADDRESS: &str = "1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ";
const PRIVATE_KEY_MIN: u128 = 0x80000000000000000;
const PRIVATE_KEY_MAX: u128 = 0xfffffffffffffffff;
const RESULT_FILE: &str = "found_key.txt";

lazy_static! {
    static ref TARGET_RIPEMD160: Vec<u8> = {
        TARGET_ADDRESS.from_base58().unwrap()[1..21].to_vec()
    };
}

fn private_key_to_address_and_pubkey(secp: &Secp256k1<secp256k1::All>, secret_key: &SecretKey) -> Option<(String, String)> {
    let public_key = PublicKey::from_secret_key(secp, secret_key);
    let pubkey_bytes = public_key.serialize(); 

    // SHA256
    let sha256 = Sha256::digest(&pubkey_bytes);
    // RIPEMD160
    let ripemd160 = Ripemd160::digest(&sha256);


    if ripemd160.as_slice() != TARGET_RIPEMD160.as_slice() {
        return None;
    }


    let mut extended_ripemd160 = vec![0x00];
    extended_ripemd160.extend_from_slice(&ripemd160);
    let checksum = Sha256::digest(&Sha256::digest(&extended_ripemd160));
    let mut binary_address = extended_ripemd160;
    binary_address.extend_from_slice(&checksum[..4]);

    // Base58
    let address = binary_address.to_base58();
    let pubkey_hex = hex::encode(pubkey_bytes);

    Some((address, pubkey_hex))
}

fn save_result(private_key_hex: &str, public_key_hex: &str, address: &str) -> bool {
    let mut file = match File::create(RESULT_FILE) {
        Ok(f) => f,
        Err(e) => {
            println!("Failed to create result file: {}", e);
            return false;
        }
    };
    let content = format!(
        "Address: {}\nPrivate Key: {}\nPublic Key: {}\n",
        address, private_key_hex, public_key_hex
    );
    if let Err(e) = file.write_all(content.as_bytes()) {
        println!("Failed to write result: {}", e);
        return false;
    }
    println!("\nResult saved to {}", RESULT_FILE);
    true
}

fn search_private_key() {
    let start_time = Instant::now();
    let total_checked = Arc::new(AtomicU64::new(0));
    let found = Arc::new(AtomicBool::new(false));
    let thread_count = num_cpus::get();
    let secp = Arc::new(Secp256k1::new());

    println!("Using {} threads", thread_count);
    println!("Starting search... Press Ctrl+C to stop.");

    let found_clone = found.clone();
    let total_checked_clone = total_checked.clone();
    ctrlc::set_handler(move || {
        if !found_clone.load(Ordering::SeqCst) {
            println!("\nStopped by user.");
            let elapsed = start_time.elapsed().as_secs_f64();
            let checked = total_checked_clone.load(Ordering::SeqCst);
            println!("Total keys checked: {}", checked);
            println!("Time elapsed: {:.2} seconds", elapsed);
            std::process::exit(0);
        }
    }).expect("Error setting Ctrl-C handler");

    let _ = thread::scope(|s| {
        for _ in 0..thread_count {
            let found = found.clone();
            let secp = secp.clone();
            let total_checked = total_checked.clone();
            s.spawn(move |_| {
                let mut rng = rand::thread_rng();
                while !found.load(Ordering::SeqCst) {
                    let privkey_int = rng.gen_range(PRIVATE_KEY_MIN..=PRIVATE_KEY_MAX);
                    let mut privkey_bytes = [0u8; 32];
                    privkey_bytes[16..32].copy_from_slice(&privkey_int.to_be_bytes()); 
                    let secret_key = match SecretKey::from_slice(&privkey_bytes) {
                        Ok(key) => key,
                        Err(_) => continue,
                    };
                    if let Some((address, pubkey_hex)) = private_key_to_address_and_pubkey(&secp, &secret_key) {
                        if address == TARGET_ADDRESS {
                            let privkey_hex = hex::encode(secret_key.as_ref());
                            println!("\nMatch found!");
                            println!("Address: {}", address);
                            println!("Private Key: {}", privkey_hex);
                            println!("Public Key: {}", pubkey_hex);
                            save_result(&privkey_hex, &pubkey_hex, &address);
                            found.store(true, Ordering::SeqCst);
                            break;
                        }
                    }
                    total_checked.fetch_add(1, Ordering::Relaxed);
                }
            });
        }

        while !found.load(Ordering::SeqCst) {
            let elapsed = start_time.elapsed().as_secs_f64();
            let checked = total_checked.load(Ordering::SeqCst);
            let speed = checked as f64 / elapsed;
            print!("\rProgress: {} keys checked | Speed: {:.2} keys/s | Elapsed: {:.2}s", checked, speed, elapsed);
            stdout().flush().unwrap();
            std::thread::sleep(Duration::from_secs(1));
        }
        Ok::<(), ()>(())
    });
}

fn main() {
    search_private_key();
}