from Crypto.Cipher import AES, DES, Blowfish
from Crypto.Util.Padding import pad, unpad
from tabulate import tabulate
import time

# Test files
files = [
    ("test_files/file_1MB.bin", 1),
    ("test_files/file_10MB.bin", 10),
    ("test_files/file_100MB.bin", 100)
]

results = []


def benchmark_algorithm(cipher_module, key, algorithm_name):

    for filename, file_size_mb in files:

        with open(filename, "rb") as f:
            data = f.read()

        cipher = cipher_module.new(key, cipher_module.MODE_ECB)

        cpu_start = time.process_time()

        # Encryption
        start = time.perf_counter()

        ciphertext = cipher.encrypt(
            pad(data, cipher.block_size)
        )

        enc_time = time.perf_counter() - start

        # Decryption
        start = time.perf_counter()

        plaintext = unpad(
            cipher.decrypt(ciphertext),
            cipher.block_size
        )

        dec_time = time.perf_counter() - start

        cpu_time = time.process_time() - cpu_start

        throughput = file_size_mb / enc_time

        results.append([
            algorithm_name,
            file_size_mb,
            round(enc_time, 6),
            round(dec_time, 6),
            round(cpu_time, 6),
            round(throughput, 2),
            plaintext == data
        ])


# AES Key (32 bytes)
aes_key = b'12345678901234567890123456789012'

benchmark_algorithm(
    AES,
    aes_key,
    "AES"
)

# DES Key (8 bytes)
des_key = b'12345678'

benchmark_algorithm(
    DES,
    des_key,
    "DES"
)

# Blowfish Key (8 bytes)
blowfish_key = b'12345678'

benchmark_algorithm(
    Blowfish,
    blowfish_key,
    "Blowfish"
)

print(
    tabulate(
        results,
        headers=[
            "Algorithm",
            "Size(MB)",
            "Enc Time(s)",
            "Dec Time(s)",
            "CPU Time(s)",
            "Throughput(MB/s)",
            "Correct"
        ],
        tablefmt="grid"
    )
)