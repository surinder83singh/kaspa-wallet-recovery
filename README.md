# Wallet Recovery Tool

This Rust-based tool derives addresses from your wallet's mnemonic and matches them against a given target address. It can also fix up to **two incorrect words** in the mnemonic, enabling recovery even with minor errors.

---

## Features

- **Address Matching**:
  - Derives **100 receive addresses** and **100 change addresses**.
  - Matches each derived address against the specified target address.

- **Mnemonic Correction**:
  - Identifies and corrects up to **two incorrect words** in the mnemonic.
  - Configurable correction modes:
    - Fix **1 word** or **2 words** in the mnemonic.

---

## Requirements

- **Rust**: Ensure you have Rust installed. You can download and install it from [Rust's official site](https://www.rust-lang.org/tools/install).
- **Dependencies**: Any required Rust crates will be fetched automatically during compilation.

---

## Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/surinder83singh/kaspa-wallet-recovery.git
cd kaspa-wallet-recovery
```

### 2. Configure Your Settings
Edit the `config.rs` file to provide your details and choose your recovery options:

#### Add Your Wallet Mnemonic and Target Address
```rust
pub const MNEMONIC: &str = "your mnemonic phrase goes here";
pub const TARGET_ADDRESS: &str = "your target address here";
```

#### Enable or Disable Two-Word Correction
Set the `FIX_2_WORDS` flag to control the correction behavior:
```rust
pub const FIX_2_WORDS: bool = true; // Set to 'true' to allow fixing up to 2 words; 'false' for fixing 1 word only.
```

### 3. Compile the Program
Run the following command to compile the program:
```bash
cargo build --release
```
This will create an optimized binary in the `target/release` directory.

### 4. Run the Program
Execute the compiled program with:
```bash
./target/release/kaspa-wallet-recovery
```

---

## Usage Notes

1. **Mnemonic Input**: Provide a mnemonic phrase in `config.rs`. The tool can fix up to two incorrect words if `FIX_2_WORDS` is enabled.
2. **Address Matching**:
   - Derives **receive addresses** (indices 0–99) and **change addresses** (indices 0–99).
   - Matches each derived address with the given target address.
3. **Privacy**: The tool runs locally and does not store or transmit your mnemonic or private data.

---

## Example Output

### When Fixing 1 Incorrect Word:
```
The application will attempt to fix up to 2 words in the mnemonic.
Match found : "mnemonic phrase goes here....."
```

### When Fixing 2 Incorrect Words:
```
The application will only attempt to fix 1 word in the mnemonic.
Match found : "mnemonic phrase goes here....."
```

---

## Disclaimer

This tool is provided **as is** without any warranty or guarantee. The authors are not responsible for any losses or damages resulting from the use of this tool. Use at your own risk.

---
