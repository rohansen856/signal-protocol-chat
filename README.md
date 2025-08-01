# Signal Protocol CLI Chat

A secure command-line chat application implementing the Signal Protocol specifications for end-to-end encryption.

## Features

- **X3DH Key Agreement**: Secure key establishment between users
- **Double Ratchet**: Forward secrecy and break-in recovery
- **XEdDSA Signatures**: Authentication using X25519 keys
- **End-to-End Encryption**: All messages are encrypted using AES-GCM
- **Persistent Storage**: Messages and keys are stored locally using Sled database
- **Terminal UI**: Clean terminal interface using Ratatui

## Protocol Implementation

This application implements the following Signal Protocol specifications:

- **X3DH (Extended Triple Diffie-Hellman)**: For initial key agreement
- **Double Ratchet**: For ongoing message encryption with forward secrecy
- **XEdDSA**: For signing prekeys with X25519 keys

## Installation

```bash
git clone https://github.com/rohansen856/signal-protocol-chat.git
cd signal-protocol-chat
cargo build --release
```

## Usage

### 1. Initialize Your Identity

Before you can chat, you need to create an identity:

```bash
cargo run -- init --name "Rohan"
```

This generates your identity keys and initial prekeys.

### 2. Add Contacts

Add contacts you want to chat with:

```bash
cargo run -- add-contact Adi 127.0.0.1:8081
```

### 3. Start Chatting

Start a chat session with a contact:

```bash
cargo run -- chat --peer Adi
```

Or start without specifying a peer (server mode):

```bash
cargo run -- chat
```

### 4. List Contacts

View your contact list:

```bash
cargo run -- contacts
```

## How It Works

### Key Exchange (X3DH)

1. When Rohan wants to chat with Adi, he fetches Adi's prekey bundle
2. Rohan performs the X3DH key agreement using:
   - Her identity key and Adi's signed prekey (DH1)
   - Her ephemeral key and Adi's identity key (DH2)
   - Her ephemeral key and Adi's signed prekey (DH3)
   - Optionally, her ephemeral key and Adi's one-time prekey (DH4)
3. A shared secret is derived using HKDF

### Message Encryption (Double Ratchet)

1. The shared secret from X3DH initializes the Double Ratchet
2. Each message is encrypted with a unique key derived from the chain keys
3. DH ratchet steps provide forward secrecy and break-in recovery
4. Out-of-order messages are handled with skipped message keys

### Security Features

- **Forward Secrecy**: Past messages remain secure even if current keys are compromised
- **Break-in Recovery**: Security is restored after key compromise
- **Authentication**: All messages are authenticated using AEAD encryption
- **Deniability**: Messages can't be proven to come from a specific sender

## Data Storage

The application stores data in `~/.signal-chat/` by default:

- Identity keys and prekeys
- Contact information
- Message history
- Session states

## Security Considerations

This is a demonstration implementation and should not be used for production security purposes. For production use, consider:

- Secure key storage (hardware security modules)
- Proper random number generation
- Side-channel attack protections
- Network security (TLS)
- Key verification mechanisms

## Architecture

```
src/
├── main.rs           # CLI entry point
├── cli/              # Terminal user interface
├── crypto/           # Cryptographic primitives
│   ├── keys.rs       # Key generation and management
│   ├── xeddsa.rs     # XEdDSA signature scheme
│   └── hkdf.rs       # Key derivation functions
├── protocol/         # Signal protocol implementation
│   ├── x3dh.rs       # X3DH key agreement
│   ├── double_ratchet.rs # Double Ratchet encryption
│   └── message.rs    # Message types
├── network/          # Peer-to-peer networking
├── storage/          # Persistent data storage
└── error.rs          # Error handling
```

## Testing

Run the test suite:

```bash
cargo test
```

Run benchmarks:

```bash
cargo bench
```

## Example Usage

Terminal 1 (Rohan):
```bash
cargo run -- init --name Rohan
cargo run -- add-contact Adi 127.0.0.1:8081
cargo run -- chat --peer Adi
```

Terminal 2 (Adi):
```bash
cargo run -- init --name Adi
cargo run -- --port 8081 chat
```

Now Rohan and Adi can securely exchange messages!

## Contributing

This implementation follows the Signal Protocol specifications. When contributing:

1. Ensure cryptographic operations are constant-time
2. Add tests for new functionality
3. Follow Rust security best practices
4. Document any protocol deviations

## License

MIT License - see LICENSE file for details.