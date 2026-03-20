# rs-mime-detect

File type detection from content (magic bytes), file extension, and MIME type mapping.

## Installation

```toml
[dependencies]
philiprehberger-mime-detect = "0.1"
```

## Usage

```rust
use philiprehberger_mime_detect::{detect_from_bytes, detect_from_extension, FileKind};

// Detect from content
let png_header = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
let file_type = detect_from_bytes(png_header).unwrap();
assert_eq!(file_type.mime_type(), "image/png");
assert_eq!(file_type.extension(), "png");
assert!(file_type.is_image());

// Detect from extension
let file_type = detect_from_extension("json").unwrap();
assert_eq!(file_type.mime_type(), "application/json");

// Detect from file path (reads content, falls back to extension)
let file_type = philiprehberger_mime_detect::detect_from_path("photo.jpg".as_ref());
```

### MIME type lookups

```rust
use philiprehberger_mime_detect::{mime_to_extension, extension_to_mime};

assert_eq!(mime_to_extension("image/png"), Some("png"));
assert_eq!(extension_to_mime("html"), Some("text/html"));
```

## Supported formats

100+ file types including:
- **Images:** JPEG, PNG, GIF, BMP, WebP, TIFF, ICO, AVIF
- **Video:** MP4, AVI, MKV/WebM
- **Audio:** MP3, WAV, FLAC, OGG, MIDI
- **Documents:** PDF, ZIP, GZIP
- **Archives:** RAR, 7Z, TAR, BZIP2, XZ, ZSTD
- **Fonts:** WOFF, WOFF2, OTF, TTF
- **Executables:** ELF, PE/EXE, Mach-O, WASM
- **Text:** HTML, CSS, JS, JSON, XML, Markdown, YAML, TOML
- **Code:** Rust, Python, Go, TypeScript

## API

| Function | Description |
|----------|-------------|
| `detect_from_bytes(bytes)` | Detect type from magic bytes |
| `detect_from_extension(ext)` | Detect type from file extension |
| `detect_from_path(path)` | Detect from file (content + extension) |
| `detect_from_reader(reader, limit)` | Detect from a reader |
| `mime_to_extension(mime)` | Get default extension for MIME type |
| `extension_to_mime(ext)` | Get MIME type for extension |

## License

MIT
