# SPDM Examples

This directory contains examples demonstrating SPDM (Security Protocol and Data Model) functionality as specified in TCG TPM 2.0 Library Specification v1.84.

## Overview

The SPDM example demonstrates how to use wolfTPM SPDM commands for secure communication channels between the host and TPM.

**Important Notes:**
- **AC_GetCapability (0x194) and AC_Send (0x195) are DEPRECATED** per TCG and will never be implemented in the reference simulator
- **PolicyTransportSPDM and GetCapability SPDM Session Info are supported**
- For real SPDM support on hardware TPMs, contact **support@wolfssl.com**

## Example

### `tcg_spdm.c` - TCG SPDM Validation

**Purpose:** Validates wolfTPM SPDM functionality per TCG spec v1.84.

**Command-line Options:**

```bash
./tcg_spdm --help                   # Show help message
./tcg_spdm --all                    # Run all validation tests
./tcg_spdm --discover-handles       # Discover AC handles
./tcg_spdm --test-policy-transport  # Test PolicyTransportSPDM command
./tcg_spdm --test-spdm-session-info # Test GetCapability SPDM session info
```

**Example Usage:**

```bash
# Run all tests
./tcg_spdm --all

# Discover AC handles
./tcg_spdm --discover-handles

# Test PolicyTransportSPDM
./tcg_spdm --test-policy-transport
```

**What Works:**
- AC handle discovery (GetCapability with TPM_CAP_HANDLES)
- PolicyTransportSPDM (0x1A1) - adds secure channel restrictions to policy
- GetCapability SPDM session info (TPM_CAP_SPDM_SESSION_INFO)

**What's Deprecated (NOT tested):**
- AC_GetCapability (0x194) - DEPRECATED per TCG spec
- AC_Send (0x195) - DEPRECATED per TCG spec

## Test Script

### `test_tcg_spdm.sh`

Test script that exercises all command-line options for `tcg_spdm` in formatted output.

**Usage:**

```bash
./tcg_spdm --help                   # Show help message
./tcg_spdm --all                    # Run all validation tests
./tcg_spdm --discover-handles       # Discover AC handles
./tcg_spdm --test-policy-transport  # Test PolicyTransportSPDM command
./tcg_spdm --test-spdm-session-info # Test GetCapability SPDM session info           
```

## Building

### Prerequisites

Build wolfTPM with SPDM support:

```bash
                          # Build with TCG simulator
./configure --enable-spdm --enable-swtpm
make
```

## Deprecated Commands

The following commands are **DEPRECATED** per TCG specification and are not implemented in wolfTPM:

- **AC_GetCapability (0x194)** - Use PolicyTransportSPDM instead
- **AC_Send (0x195)** - Use PolicyTransportSPDM instead

## Support

For production use with hardware TPMs and full SPDM protocol support, contact:

**support@wolfssl.com**
