# rs-mime-detect

[![CI](https://github.com/philiprehberger/rs-mime-detect/actions/workflows/ci.yml/badge.svg)](https://github.com/philiprehberger/rs-mime-detect/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/philiprehberger-mime-detect.svg)](https://crates.io/crates/philiprehberger-mime-detect)
[![Last updated](https://img.shields.io/github/last-commit/philiprehberger/rs-mime-detect)](https://github.com/philiprehberger/rs-mime-detect/commits/main)

File type detection from content (magic bytes), file extension, and MIME type mapping

## Installation

```toml
[dependencies]
philiprehberger-mime-detect = "0.2.0"
```

## Usage

```rust
use philiprehberger_mime_detect::{detect_from_bytes, detect_from_extension, detect_from_filename, FileKind};

// Detect from content
let png_header = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
let file_type = detect_from_bytes(png_header).unwrap();
assert_eq!(file_type.mime_type(), "image/png");
assert_eq!(file_type.extension(), "png");
assert!(file_type.is_image());

// Detect from extension
let file_type = detect_from_extension("json").unwrap();
assert_eq!(file_type.mime_type(), "application/json");

// Detect from filename
let file_type = detect_from_filename("report.pdf").unwrap();
assert_eq!(file_type.mime_type(), "application/pdf");

// Detect from file path (reads content, falls back to extension)
let file_type = philiprehberger_mime_detect::detect_from_path("photo.jpg".as_ref());
```

### MIME type lookups

```rust
use philiprehberger_mime_detect::{mime_to_extension, extension_to_mime};

assert_eq!(mime_to_extension("image/png"), Some("png"));
assert_eq!(extension_to_mime("html"), Some("text/html"));
```

## API

| Function | Description |
|----------|-------------|
| `detect_from_bytes(bytes)` | Detect type from magic bytes |
| `detect_from_extension(ext)` | Detect type from file extension |
| `detect_from_filename(name)` | Detect type from a filename string |
| `detect_from_path(path)` | Detect from file (content + extension) |
| `detect_from_reader(reader, limit)` | Detect from a reader |
| `mime_to_extension(mime)` | Get default extension for MIME type |
| `extension_to_mime(ext)` | Get MIME type for extension |

## Development

```bash
cargo test
cargo clippy -- -D warnings
```

## Support

If you find this project useful:

⭐ [Star the repo](https://github.com/philiprehberger/rs-mime-detect)

🐛 [Report issues](https://github.com/philiprehberger/rs-mime-detect/issues?q=is%3Aissue+is%3Aopen+label%3Abug)

💡 [Suggest features](https://github.com/philiprehberger/rs-mime-detect/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement)

❤️ [Sponsor development](https://github.com/sponsors/philiprehberger)

🌐 [All Open Source Projects](https://philiprehberger.com/open-source-packages)

💻 [GitHub Profile](https://github.com/philiprehberger)

🔗 [LinkedIn Profile](https://www.linkedin.com/in/philiprehberger)

## License

[MIT](LICENSE)
