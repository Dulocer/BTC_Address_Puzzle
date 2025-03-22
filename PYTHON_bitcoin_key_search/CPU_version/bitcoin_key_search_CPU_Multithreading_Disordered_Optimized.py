import ecdsa
import hashlib
import base58
import time
import sys
import signal
import logging
from multiprocessing import Pool, cpu_count
import random

# Target address and range
TARGET_ADDRESS = "1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ"
PRIVATE_KEY_MIN = 0x80000000000000000
PRIVATE_KEY_MAX = 0xfffffffffffffffff
RESULT_FILE = "found_key.txt"

# Precompute the RIPEMD160 hash of the target address
TARGET_RIPEMD160 = base58.b58decode(TARGET_ADDRESS)[1:-4]  # Remove the version byte and checksum

# Pre-initialize hash function
SHA256 = hashlib.sha256
RIPEMD160 = lambda x: hashlib.new("ripemd160", x).digest()

"""
# Log Settings
logging.basicConfig(
    filename="key_search.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)
"""

def private_key_to_address_and_pubkey(private_key_int):
    """
    Convert a private key to a Bitcoin address and public key, aborting early at the RIPEMD160 stage.

    Args:
    private_key_int (int): Integer form of the private key.

    Returns:
    tuple: (address, public_key_hex) or (None, None) on mismatch or failure.
    """
    try:
        private_key_bytes = private_key_int.to_bytes(32, 'big')
        sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        x = vk.to_string()[:32]
        prefix = b'\x02' if int.from_bytes(vk.to_string()[32:], 'big') % 2 == 0 else b'\x03'
        public_key_compressed = prefix + x
        
        sha256_hash = SHA256(public_key_compressed).digest()
        ripemd160_hash = RIPEMD160(sha256_hash)
        
        # Early termination at RIPEMD160 stage
        if ripemd160_hash != TARGET_RIPEMD160:
            return None, None
        
        # If RIPEMD160 matches, continue generating the full address
        extended_ripemd160 = b'\x00' + ripemd160_hash
        checksum = SHA256(SHA256(extended_ripemd160).digest()).digest()[:4]
        binary_address = extended_ripemd160 + checksum
        address = base58.b58encode(binary_address).decode('ascii')
        
        return address, public_key_compressed.hex()
    except (ValueError, ecdsa.keys.MalformedPointError):
        return None, None

def save_result(private_key_hex, public_key_hex, address):
    """Save the found private key, public key and address to a file."""
    try:
        with open(RESULT_FILE, "w") as f:
            f.write(f"Address: {address}\n")
            f.write(f"Private Key: {private_key_hex}\n")
            f.write(f"Public Key: {public_key_hex}\n")
        logging.info(f"Match found and saved: {address}")
        print(f"\nResult saved to {RESULT_FILE}")
        return True
    except IOError as e:
        logging.error(f"Failed to save result: {e}")
        print(f"Failed to save result: {e}")
        return False

def check_random_key(_):
    """Check if the random private key matches the target address."""
    private_key_int = random.randint(PRIVATE_KEY_MIN, PRIVATE_KEY_MAX)
    address, public_key_hex = private_key_to_address_and_pubkey(private_key_int)
    if address == TARGET_ADDRESS:  # Double confirmation to ensure accuracy
        private_key_hex = private_key_int.to_bytes(32, 'big').hex()
        print(f"\nMatch found!")
        print(f"Address: {address}")
        print(f"Private Key: {private_key_hex}")
        print(f"Public Key: {public_key_hex}")
        return private_key_hex, public_key_hex, address
    return None

def search_private_key():
    """The main function that performs the private key search uses multi-process parallel processing."""
    start_time = time.time()  # Record program start time
    total_checked = 0
    num_processes = cpu_count()
    batch_size = num_processes * 500 # The number of keys to process in batches
    last_update_time = start_time  # Used to control updates per second
    
    print(f"Using {num_processes} processes")
    print("Starting search... Press Ctrl+C to stop.")
    logging.info(f"Search started with {num_processes} processes")

    def signal_handler(sig, frame):
        print("\nReceived termination signal. Exiting gracefully...")
        logging.info("Search terminated by signal")
        sys.exit(0)

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    try:
        with Pool(processes=num_processes) as pool:
            while True:
                results = pool.map(check_random_key, range(batch_size))
                total_checked += batch_size
                
                match = next((r for r in results if r), None)
                if match:
                    save_result(*match)
                    break
                
                current_time = time.time()
                elapsed_time = current_time - start_time 
                if current_time - last_update_time >= 1: 
                    speed = total_checked / elapsed_time
                    sys.stdout.write(f"\rProgress: {total_checked} keys checked | "
                                   f"Speed: {speed:.2f} keys/s | "
                                   f"Elapsed: {elapsed_time:.2f}s")
                    sys.stdout.flush()
                    logging.info(f"Progress: {total_checked} keys, Speed: {speed:.2f} keys/s")
                    last_update_time = current_time 
                    
    except KeyboardInterrupt:
        print("\nStopped by user.")
        elapsed_time = time.time() - start_time
        logging.info(f"Stopped by user. Total keys checked: {total_checked}")
        print(f"Total keys checked: {total_checked}")
        print(f"Time elapsed: {elapsed_time:.2f} seconds")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    search_private_key()
