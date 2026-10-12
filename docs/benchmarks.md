# Benchmarks

This page shows how fast the supported TPM 2.0 devices run common operations, measured with the `examples/bench/bench` program, plus the first post-quantum numbers from SEALSQ QVault silicon.

## About these numbers

These are representative captures from real hardware, taken on different host boards and bus speeds. Results vary with the TPM firmware version, bus clock, host platform and build options, so treat them as a guide and run `./examples/bench/bench` on your own setup.

## TPM 2.0 benchmarks by device

Average latency per operation, in milliseconds (lower is better). RSA-2048 key generation is a one-off provisioning cost.

| Device | Bus | RSA-2048 key gen | RSA-2048 private | ECDSA P-256 sign | ECDSA P-256 verify |
|---|---|---|---|---|---|
| Infineon OPTIGA SLB9670 | SPI, 43 MHz | 2196.2 | 163.2 | 68.9 | 113.5 |
| Infineon OPTIGA SLB9672 | SPI, 43 MHz | 1567.7 | 77.0 | 35.6 | 24.1 |
| Infineon OPTIGA SLB9673 | I2C, 400 kHz | 1910.6 | 168.1 | 72.1 | 57.9 |
| STMicro ST33KTPM2XSPI | SPI, 33 MHz | 1944.1 | 90.8 | 25.3 | 36.5 |
| STMicro ST33TPHF2XSPI | SPI, 33 MHz | 7455.0 | 247.8 | 42.3 | 74.0 |
| Microchip ATTPM20 | SPI, 33 MHz | 5275.9 | 117.7 | 58.7 | 43.0 |
| Nations Z32H330 | SPI, 33 MHz | 2183.8 | 133.2 | 23.4 | 36.8 |
| Nations NS350 | SPI, 33 MHz | 2378.9 | 51.7 | 16.8 | 21.9 |
| Nuvoton NPCT650 | not stated | 4479.2 | 540.9 | 190.1 | 265.2 |
| Nuvoton NPCT750 | SPI, 43 MHz | 3408.7 | 70.3 | 56.4 | 39.2 |
| NVIDIA Jetson Orin fTPM (OP-TEE) | `/dev/tpmrm0` | 736.4 | 11.9 | 45.1 | 31.7 |

The README captures for the ST33TPHF2XSPI RSA key generation ran a single operation, so that figure is the least reliable in the table.

Example output from `./examples/bench/bench` on an Infineon OPTIGA SLB9672 at 43 MHz:

```
./examples/bench/bench
TPM2 Benchmark using Wrapper API's
	Use Parameter Encryption: NULL
Loading SRK: Storage 0x81000200 (282 bytes)
RNG                 24 KB took 1.070 seconds,   22.429 KB/s
Benchmark symmetric AES-128-CBC-enc not supported!
Benchmark symmetric AES-128-CBC-dec not supported!
Benchmark symmetric AES-256-CBC-enc not supported!
Benchmark symmetric AES-256-CBC-dec not supported!
Benchmark symmetric AES-128-CTR-enc not supported!
Benchmark symmetric AES-128-CTR-dec not supported!
Benchmark symmetric AES-256-CTR-enc not supported!
Benchmark symmetric AES-256-CTR-dec not supported!
AES-128-CFB-enc     86 KB took 1.001 seconds,   85.890 KB/s
AES-128-CFB-dec     88 KB took 1.020 seconds,   86.267 KB/s
AES-256-CFB-enc     86 KB took 1.023 seconds,   84.073 KB/s
AES-256-CFB-dec     86 KB took 1.019 seconds,   84.370 KB/s
SHA1                88 KB took 1.021 seconds,   86.155 KB/s
SHA256              86 KB took 1.015 seconds,   84.717 KB/s
SHA384              90 KB took 1.007 seconds,   89.405 KB/s
RSA     2048 key gen       10 ops took 15.677 sec, avg 1567.678 ms, 0.638 ops/sec
RSA     2048 Public       110 ops took 1.000 sec, avg 9.095 ms, 109.951 ops/sec
RSA     2048 Private       14 ops took 1.078 sec, avg 76.996 ms, 12.988 ops/sec
RSA     2048 Pub  OAEP     51 ops took 1.012 sec, avg 19.838 ms, 50.408 ops/sec
RSA     2048 Priv OAEP     12 ops took 1.053 sec, avg 87.738 ms, 11.398 ops/sec
ECC      256 key gen        8 ops took 1.088 sec, avg 135.956 ms, 7.355 ops/sec
ECDSA    256 sign          29 ops took 1.033 sec, avg 35.621 ms, 28.073 ops/sec
ECDSA    256 verify        42 ops took 1.013 sec, avg 24.114 ms, 41.470 ops/sec
ECDHE    256 agree         16 ops took 1.055 sec, avg 65.948 ms, 15.164 ops/sec
```

Devices that do not support a mode print "not supported" for it.

## Post-quantum (SEALSQ QVault)

These numbers were measured with `examples/bench/bench` on a Raspberry Pi 5 driving the SEALSQ QVault TPM over SPI. SEALSQ positions this part as the first post-quantum TPM in silicon.

| Operation | Avg latency | Throughput |
|---|---|---|
| ML-DSA-65 key gen | 2044.7 ms | 0.49 ops/s |
| ML-DSA-65 sign | 581.0 ms | 1.72 ops/s |
| ML-DSA-65 verify | 163.1 ms | 6.13 ops/s |
| ML-KEM-768 key gen | 800.8 ms | 1.25 ops/s |
| ML-KEM-768 encapsulate | 211.8 ms | 4.72 ops/s |
| ML-KEM-768 decapsulate | 425.5 ms | 2.35 ops/s |

Key generation is a one-off provisioning cost. The ECDSA figures above come from different TPMs, host boards, buses, and firmware, so they are not a like-for-like comparison with these ML-DSA numbers. To compare ECDSA and PQC latencies, run `./examples/bench/bench` for both on the same TPM, host, bus, and build.

## See Also

- [Testing and CI](testing.md)
- [Cited Sources](cited-sources.md)
- [Release Notes](release-notes.md)
