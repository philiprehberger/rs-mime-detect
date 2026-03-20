//! File type detection from content (magic bytes), file extension, and MIME type mapping.
//!
//! This crate provides functions to detect file types using magic byte signatures,
//! file extensions, or a combination of both. It supports 100+ file types across
//! images, video, audio, documents, archives, fonts, executables, and more.
//!
//! # Examples
//!
//! ```
//! use philiprehberger_mime_detect::{detect_from_bytes, detect_from_extension};
//!
//! // Detect from content bytes
//! let png = detect_from_bytes(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]).unwrap();
//! assert_eq!(png.mime_type(), "image/png");
//!
//! // Detect from file extension
//! let json = detect_from_extension("json").unwrap();
//! assert_eq!(json.mime_type(), "application/json");
//! ```

use std::io::Read;
use std::path::Path;

/// Categorization of a file type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileKind {
    /// Image files (JPEG, PNG, GIF, etc.)
    Image,
    /// Video files (MP4, AVI, MKV, etc.)
    Video,
    /// Audio files (MP3, WAV, FLAC, etc.)
    Audio,
    /// Document files (PDF, etc.)
    Document,
    /// Archive files (ZIP, RAR, 7Z, TAR, etc.)
    Archive,
    /// Font files (WOFF, WOFF2, OTF, TTF)
    Font,
    /// Executable files (ELF, PE, Mach-O, WASM)
    Executable,
    /// Text and code files, or unclassified types
    Other,
}

/// Represents a detected file type with its MIME type, extension, and kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileType {
    mime: &'static str,
    extension: &'static str,
    kind: FileKind,
}

impl FileType {
    /// Returns the MIME type string (e.g., `"image/png"`).
    pub fn mime_type(&self) -> &str {
        self.mime
    }

    /// Returns the default file extension without a leading dot (e.g., `"png"`).
    pub fn extension(&self) -> &str {
        self.extension
    }

    /// Returns the [`FileKind`] category.
    pub fn kind(&self) -> FileKind {
        self.kind
    }

    /// Returns `true` if this is an image type.
    pub fn is_image(&self) -> bool {
        self.kind == FileKind::Image
    }

    /// Returns `true` if this is a video type.
    pub fn is_video(&self) -> bool {
        self.kind == FileKind::Video
    }

    /// Returns `true` if this is an audio type.
    pub fn is_audio(&self) -> bool {
        self.kind == FileKind::Audio
    }

    /// Returns `true` if the MIME type starts with `"text/"`.
    pub fn is_text(&self) -> bool {
        self.mime.starts_with("text/")
    }

    /// Returns `true` if this is an archive type.
    pub fn is_archive(&self) -> bool {
        self.kind == FileKind::Archive
    }
}

struct MagicSignature {
    offset: usize,
    magic: &'static [u8],
    file_type: FileType,
}

/// Magic byte signatures for content-based detection.
///
/// Order matters: more specific signatures should come before less specific ones.
/// For example, AVIF (ftyp + avif) must be checked before generic MP4 (ftyp).
const SIGNATURES: &[MagicSignature] = &[
    // Images
    MagicSignature {
        offset: 0,
        magic: &[0xFF, 0xD8, 0xFF],
        file_type: FileType { mime: "image/jpeg", extension: "jpg", kind: FileKind::Image },
    },
    MagicSignature {
        offset: 0,
        magic: &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        file_type: FileType { mime: "image/png", extension: "png", kind: FileKind::Image },
    },
    MagicSignature {
        offset: 0,
        magic: b"GIF87a",
        file_type: FileType { mime: "image/gif", extension: "gif", kind: FileKind::Image },
    },
    MagicSignature {
        offset: 0,
        magic: b"GIF89a",
        file_type: FileType { mime: "image/gif", extension: "gif", kind: FileKind::Image },
    },
    MagicSignature {
        offset: 0,
        magic: &[0x42, 0x4D],
        file_type: FileType { mime: "image/bmp", extension: "bmp", kind: FileKind::Image },
    },
    MagicSignature {
        offset: 0,
        magic: &[0x49, 0x49, 0x2A, 0x00],
        file_type: FileType { mime: "image/tiff", extension: "tiff", kind: FileKind::Image },
    },
    MagicSignature {
        offset: 0,
        magic: &[0x4D, 0x4D, 0x00, 0x2A],
        file_type: FileType { mime: "image/tiff", extension: "tiff", kind: FileKind::Image },
    },
    MagicSignature {
        offset: 0,
        magic: &[0x00, 0x00, 0x01, 0x00],
        file_type: FileType { mime: "image/x-icon", extension: "ico", kind: FileKind::Image },
    },
    // AVIF (ftyp + avif at offset 4) — must be before generic MP4 ftyp
    MagicSignature {
        offset: 4,
        magic: b"ftypavif",
        file_type: FileType { mime: "image/avif", extension: "avif", kind: FileKind::Image },
    },
    // Video — MP4 generic ftyp (after AVIF)
    MagicSignature {
        offset: 4,
        magic: b"ftyp",
        file_type: FileType { mime: "video/mp4", extension: "mp4", kind: FileKind::Video },
    },
    MagicSignature {
        offset: 0,
        magic: &[0x1A, 0x45, 0xDF, 0xA3],
        file_type: FileType { mime: "video/x-matroska", extension: "mkv", kind: FileKind::Video },
    },
    // Audio
    MagicSignature {
        offset: 0,
        magic: b"ID3",
        file_type: FileType { mime: "audio/mpeg", extension: "mp3", kind: FileKind::Audio },
    },
    MagicSignature {
        offset: 0,
        magic: &[0xFF, 0xFB],
        file_type: FileType { mime: "audio/mpeg", extension: "mp3", kind: FileKind::Audio },
    },
    MagicSignature {
        offset: 0,
        magic: &[0xFF, 0xF3],
        file_type: FileType { mime: "audio/mpeg", extension: "mp3", kind: FileKind::Audio },
    },
    MagicSignature {
        offset: 0,
        magic: &[0xFF, 0xF2],
        file_type: FileType { mime: "audio/mpeg", extension: "mp3", kind: FileKind::Audio },
    },
    MagicSignature {
        offset: 0,
        magic: b"fLaC",
        file_type: FileType { mime: "audio/flac", extension: "flac", kind: FileKind::Audio },
    },
    MagicSignature {
        offset: 0,
        magic: b"OggS",
        file_type: FileType { mime: "audio/ogg", extension: "ogg", kind: FileKind::Audio },
    },
    MagicSignature {
        offset: 0,
        magic: b"MThd",
        file_type: FileType { mime: "audio/midi", extension: "mid", kind: FileKind::Audio },
    },
    // Documents
    MagicSignature {
        offset: 0,
        magic: b"%PDF",
        file_type: FileType { mime: "application/pdf", extension: "pdf", kind: FileKind::Document },
    },
    // Archives — specific signatures before ZIP
    MagicSignature {
        offset: 0,
        magic: &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07],
        file_type: FileType { mime: "application/x-rar-compressed", extension: "rar", kind: FileKind::Archive },
    },
    MagicSignature {
        offset: 0,
        magic: &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
        file_type: FileType { mime: "application/x-7z-compressed", extension: "7z", kind: FileKind::Archive },
    },
    MagicSignature {
        offset: 257,
        magic: b"ustar",
        file_type: FileType { mime: "application/x-tar", extension: "tar", kind: FileKind::Archive },
    },
    MagicSignature {
        offset: 0,
        magic: &[0x42, 0x5A, 0x68],
        file_type: FileType { mime: "application/x-bzip2", extension: "bz2", kind: FileKind::Archive },
    },
    MagicSignature {
        offset: 0,
        magic: &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00],
        file_type: FileType { mime: "application/x-xz", extension: "xz", kind: FileKind::Archive },
    },
    MagicSignature {
        offset: 0,
        magic: &[0x28, 0xB5, 0x2F, 0xFD],
        file_type: FileType { mime: "application/zstd", extension: "zst", kind: FileKind::Archive },
    },
    MagicSignature {
        offset: 0,
        magic: &[0x1F, 0x8B],
        file_type: FileType { mime: "application/gzip", extension: "gz", kind: FileKind::Archive },
    },
    MagicSignature {
        offset: 0,
        magic: &[0x50, 0x4B, 0x03, 0x04],
        file_type: FileType { mime: "application/zip", extension: "zip", kind: FileKind::Archive },
    },
    // Fonts
    MagicSignature {
        offset: 0,
        magic: b"wOFF",
        file_type: FileType { mime: "font/woff", extension: "woff", kind: FileKind::Font },
    },
    MagicSignature {
        offset: 0,
        magic: b"wOF2",
        file_type: FileType { mime: "font/woff2", extension: "woff2", kind: FileKind::Font },
    },
    MagicSignature {
        offset: 0,
        magic: b"OTTO",
        file_type: FileType { mime: "font/otf", extension: "otf", kind: FileKind::Font },
    },
    MagicSignature {
        offset: 0,
        magic: &[0x00, 0x01, 0x00, 0x00],
        file_type: FileType { mime: "font/ttf", extension: "ttf", kind: FileKind::Font },
    },
    // Executables
    MagicSignature {
        offset: 0,
        magic: &[0x7F, 0x45, 0x4C, 0x46],
        file_type: FileType { mime: "application/x-elf", extension: "elf", kind: FileKind::Executable },
    },
    MagicSignature {
        offset: 0,
        magic: &[0x4D, 0x5A],
        file_type: FileType { mime: "application/vnd.microsoft.portable-executable", extension: "exe", kind: FileKind::Executable },
    },
    MagicSignature {
        offset: 0,
        magic: &[0xFE, 0xED, 0xFA, 0xCE],
        file_type: FileType { mime: "application/x-mach-binary", extension: "macho", kind: FileKind::Executable },
    },
    MagicSignature {
        offset: 0,
        magic: &[0xFE, 0xED, 0xFA, 0xCF],
        file_type: FileType { mime: "application/x-mach-binary", extension: "macho", kind: FileKind::Executable },
    },
    MagicSignature {
        offset: 0,
        magic: &[0xCF, 0xFA, 0xED, 0xFE],
        file_type: FileType { mime: "application/x-mach-binary", extension: "macho", kind: FileKind::Executable },
    },
    MagicSignature {
        offset: 0,
        magic: &[0xCE, 0xFA, 0xED, 0xFE],
        file_type: FileType { mime: "application/x-mach-binary", extension: "macho", kind: FileKind::Executable },
    },
    MagicSignature {
        offset: 0,
        magic: &[0x00, 0x61, 0x73, 0x6D],
        file_type: FileType { mime: "application/wasm", extension: "wasm", kind: FileKind::Executable },
    },
    // Other
    MagicSignature {
        offset: 0,
        magic: b"SQLite format 3\0",
        file_type: FileType { mime: "application/x-sqlite3", extension: "sqlite", kind: FileKind::Other },
    },
];

/// Extension-to-MIME mapping entry.
struct ExtMapping {
    extension: &'static str,
    mime: &'static str,
    kind: FileKind,
}

const EXT_MAP: &[ExtMapping] = &[
    // Images
    ExtMapping { extension: "jpg", mime: "image/jpeg", kind: FileKind::Image },
    ExtMapping { extension: "jpeg", mime: "image/jpeg", kind: FileKind::Image },
    ExtMapping { extension: "png", mime: "image/png", kind: FileKind::Image },
    ExtMapping { extension: "gif", mime: "image/gif", kind: FileKind::Image },
    ExtMapping { extension: "bmp", mime: "image/bmp", kind: FileKind::Image },
    ExtMapping { extension: "webp", mime: "image/webp", kind: FileKind::Image },
    ExtMapping { extension: "tiff", mime: "image/tiff", kind: FileKind::Image },
    ExtMapping { extension: "tif", mime: "image/tiff", kind: FileKind::Image },
    ExtMapping { extension: "ico", mime: "image/x-icon", kind: FileKind::Image },
    ExtMapping { extension: "avif", mime: "image/avif", kind: FileKind::Image },
    ExtMapping { extension: "svg", mime: "image/svg+xml", kind: FileKind::Image },
    // Video
    ExtMapping { extension: "mp4", mime: "video/mp4", kind: FileKind::Video },
    ExtMapping { extension: "m4v", mime: "video/mp4", kind: FileKind::Video },
    ExtMapping { extension: "avi", mime: "video/x-msvideo", kind: FileKind::Video },
    ExtMapping { extension: "mkv", mime: "video/x-matroska", kind: FileKind::Video },
    ExtMapping { extension: "webm", mime: "video/webm", kind: FileKind::Video },
    ExtMapping { extension: "mov", mime: "video/quicktime", kind: FileKind::Video },
    ExtMapping { extension: "wmv", mime: "video/x-ms-wmv", kind: FileKind::Video },
    ExtMapping { extension: "flv", mime: "video/x-flv", kind: FileKind::Video },
    // Audio
    ExtMapping { extension: "mp3", mime: "audio/mpeg", kind: FileKind::Audio },
    ExtMapping { extension: "wav", mime: "audio/wav", kind: FileKind::Audio },
    ExtMapping { extension: "flac", mime: "audio/flac", kind: FileKind::Audio },
    ExtMapping { extension: "ogg", mime: "audio/ogg", kind: FileKind::Audio },
    ExtMapping { extension: "mid", mime: "audio/midi", kind: FileKind::Audio },
    ExtMapping { extension: "midi", mime: "audio/midi", kind: FileKind::Audio },
    ExtMapping { extension: "aac", mime: "audio/aac", kind: FileKind::Audio },
    ExtMapping { extension: "wma", mime: "audio/x-ms-wma", kind: FileKind::Audio },
    ExtMapping { extension: "m4a", mime: "audio/mp4", kind: FileKind::Audio },
    // Documents
    ExtMapping { extension: "pdf", mime: "application/pdf", kind: FileKind::Document },
    ExtMapping { extension: "doc", mime: "application/msword", kind: FileKind::Document },
    ExtMapping { extension: "docx", mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", kind: FileKind::Document },
    ExtMapping { extension: "xls", mime: "application/vnd.ms-excel", kind: FileKind::Document },
    ExtMapping { extension: "xlsx", mime: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", kind: FileKind::Document },
    ExtMapping { extension: "ppt", mime: "application/vnd.ms-powerpoint", kind: FileKind::Document },
    ExtMapping { extension: "pptx", mime: "application/vnd.openxmlformats-officedocument.presentationml.presentation", kind: FileKind::Document },
    // Archives
    ExtMapping { extension: "zip", mime: "application/zip", kind: FileKind::Archive },
    ExtMapping { extension: "gz", mime: "application/gzip", kind: FileKind::Archive },
    ExtMapping { extension: "gzip", mime: "application/gzip", kind: FileKind::Archive },
    ExtMapping { extension: "rar", mime: "application/x-rar-compressed", kind: FileKind::Archive },
    ExtMapping { extension: "7z", mime: "application/x-7z-compressed", kind: FileKind::Archive },
    ExtMapping { extension: "tar", mime: "application/x-tar", kind: FileKind::Archive },
    ExtMapping { extension: "bz2", mime: "application/x-bzip2", kind: FileKind::Archive },
    ExtMapping { extension: "xz", mime: "application/x-xz", kind: FileKind::Archive },
    ExtMapping { extension: "zst", mime: "application/zstd", kind: FileKind::Archive },
    ExtMapping { extension: "lz", mime: "application/x-lzip", kind: FileKind::Archive },
    // Fonts
    ExtMapping { extension: "woff", mime: "font/woff", kind: FileKind::Font },
    ExtMapping { extension: "woff2", mime: "font/woff2", kind: FileKind::Font },
    ExtMapping { extension: "otf", mime: "font/otf", kind: FileKind::Font },
    ExtMapping { extension: "ttf", mime: "font/ttf", kind: FileKind::Font },
    ExtMapping { extension: "eot", mime: "application/vnd.ms-fontobject", kind: FileKind::Font },
    // Executables
    ExtMapping { extension: "exe", mime: "application/vnd.microsoft.portable-executable", kind: FileKind::Executable },
    ExtMapping { extension: "elf", mime: "application/x-elf", kind: FileKind::Executable },
    ExtMapping { extension: "macho", mime: "application/x-mach-binary", kind: FileKind::Executable },
    ExtMapping { extension: "wasm", mime: "application/wasm", kind: FileKind::Executable },
    ExtMapping { extension: "dll", mime: "application/vnd.microsoft.portable-executable", kind: FileKind::Executable },
    // Text
    ExtMapping { extension: "html", mime: "text/html", kind: FileKind::Other },
    ExtMapping { extension: "htm", mime: "text/html", kind: FileKind::Other },
    ExtMapping { extension: "css", mime: "text/css", kind: FileKind::Other },
    ExtMapping { extension: "js", mime: "text/javascript", kind: FileKind::Other },
    ExtMapping { extension: "mjs", mime: "text/javascript", kind: FileKind::Other },
    ExtMapping { extension: "json", mime: "application/json", kind: FileKind::Other },
    ExtMapping { extension: "xml", mime: "application/xml", kind: FileKind::Other },
    ExtMapping { extension: "txt", mime: "text/plain", kind: FileKind::Other },
    ExtMapping { extension: "csv", mime: "text/csv", kind: FileKind::Other },
    ExtMapping { extension: "md", mime: "text/markdown", kind: FileKind::Other },
    ExtMapping { extension: "markdown", mime: "text/markdown", kind: FileKind::Other },
    ExtMapping { extension: "yaml", mime: "application/yaml", kind: FileKind::Other },
    ExtMapping { extension: "yml", mime: "application/yaml", kind: FileKind::Other },
    ExtMapping { extension: "toml", mime: "application/toml", kind: FileKind::Other },
    ExtMapping { extension: "ini", mime: "text/plain", kind: FileKind::Other },
    ExtMapping { extension: "cfg", mime: "text/plain", kind: FileKind::Other },
    ExtMapping { extension: "conf", mime: "text/plain", kind: FileKind::Other },
    ExtMapping { extension: "log", mime: "text/plain", kind: FileKind::Other },
    // Code
    ExtMapping { extension: "rs", mime: "text/x-rust", kind: FileKind::Other },
    ExtMapping { extension: "py", mime: "text/x-python", kind: FileKind::Other },
    ExtMapping { extension: "go", mime: "text/x-go", kind: FileKind::Other },
    ExtMapping { extension: "ts", mime: "text/typescript", kind: FileKind::Other },
    ExtMapping { extension: "tsx", mime: "text/tsx", kind: FileKind::Other },
    ExtMapping { extension: "jsx", mime: "text/jsx", kind: FileKind::Other },
    ExtMapping { extension: "java", mime: "text/x-java-source", kind: FileKind::Other },
    ExtMapping { extension: "c", mime: "text/x-c", kind: FileKind::Other },
    ExtMapping { extension: "cpp", mime: "text/x-c++", kind: FileKind::Other },
    ExtMapping { extension: "h", mime: "text/x-c", kind: FileKind::Other },
    ExtMapping { extension: "hpp", mime: "text/x-c++", kind: FileKind::Other },
    ExtMapping { extension: "rb", mime: "text/x-ruby", kind: FileKind::Other },
    ExtMapping { extension: "php", mime: "text/x-php", kind: FileKind::Other },
    ExtMapping { extension: "swift", mime: "text/x-swift", kind: FileKind::Other },
    ExtMapping { extension: "kt", mime: "text/x-kotlin", kind: FileKind::Other },
    ExtMapping { extension: "scala", mime: "text/x-scala", kind: FileKind::Other },
    ExtMapping { extension: "sh", mime: "text/x-shellscript", kind: FileKind::Other },
    ExtMapping { extension: "bash", mime: "text/x-shellscript", kind: FileKind::Other },
    ExtMapping { extension: "zsh", mime: "text/x-shellscript", kind: FileKind::Other },
    ExtMapping { extension: "fish", mime: "text/x-shellscript", kind: FileKind::Other },
    ExtMapping { extension: "sql", mime: "application/sql", kind: FileKind::Other },
    ExtMapping { extension: "graphql", mime: "application/graphql", kind: FileKind::Other },
    ExtMapping { extension: "wsdl", mime: "application/wsdl+xml", kind: FileKind::Other },
    // Data
    ExtMapping { extension: "sqlite", mime: "application/x-sqlite3", kind: FileKind::Other },
    ExtMapping { extension: "db", mime: "application/x-sqlite3", kind: FileKind::Other },
];

/// RIFF sub-format identifiers at offset 8.
const RIFF_MAGIC: &[u8] = b"RIFF";

struct RiffSubType {
    sub_id: &'static [u8; 4],
    file_type: FileType,
}

const RIFF_SUBTYPES: &[RiffSubType] = &[
    RiffSubType {
        sub_id: b"WEBP",
        file_type: FileType { mime: "image/webp", extension: "webp", kind: FileKind::Image },
    },
    RiffSubType {
        sub_id: b"AVI ",
        file_type: FileType { mime: "video/x-msvideo", extension: "avi", kind: FileKind::Video },
    },
    RiffSubType {
        sub_id: b"WAVE",
        file_type: FileType { mime: "audio/wav", extension: "wav", kind: FileKind::Audio },
    },
];

/// Checks if bytes start with the RIFF header and matches a known sub-format.
fn detect_riff(bytes: &[u8]) -> Option<FileType> {
    if bytes.len() < 12 {
        return None;
    }
    if &bytes[0..4] != RIFF_MAGIC {
        return None;
    }
    let sub_id = &bytes[8..12];
    for riff in RIFF_SUBTYPES {
        if sub_id == riff.sub_id {
            return Some(riff.file_type.clone());
        }
    }
    None
}

/// Detects a file type from content bytes using magic number signatures.
///
/// Returns `None` if the content does not match any known signature.
///
/// # Examples
///
/// ```
/// use philiprehberger_mime_detect::detect_from_bytes;
///
/// let result = detect_from_bytes(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
/// assert_eq!(result.unwrap().mime_type(), "image/png");
/// ```
pub fn detect_from_bytes(bytes: &[u8]) -> Option<FileType> {
    if bytes.is_empty() {
        return None;
    }

    // Check RIFF-based formats first (WebP, AVI, WAV)
    if let Some(ft) = detect_riff(bytes) {
        return Some(ft);
    }

    // Check all magic signatures
    for sig in SIGNATURES {
        let end = sig.offset + sig.magic.len();
        if bytes.len() >= end && &bytes[sig.offset..end] == sig.magic {
            return Some(sig.file_type.clone());
        }
    }

    None
}

/// Normalizes an extension by stripping a leading dot and lowercasing.
fn normalize_ext(ext: &str) -> String {
    let ext = ext.strip_prefix('.').unwrap_or(ext);
    ext.to_ascii_lowercase()
}

/// Detects a file type from a file extension.
///
/// The extension can be provided with or without a leading dot, and is
/// matched case-insensitively.
///
/// # Examples
///
/// ```
/// use philiprehberger_mime_detect::detect_from_extension;
///
/// let ft = detect_from_extension(".PDF").unwrap();
/// assert_eq!(ft.mime_type(), "application/pdf");
/// ```
pub fn detect_from_extension(ext: &str) -> Option<FileType> {
    let normalized = normalize_ext(ext);
    for entry in EXT_MAP {
        if entry.extension == normalized {
            return Some(FileType {
                mime: entry.mime,
                extension: entry.extension,
                kind: entry.kind,
            });
        }
    }
    None
}

/// Detects a file type from a file path.
///
/// Reads the first 512 bytes of the file for content-based detection. If that
/// fails, falls back to extension-based detection. If the file cannot be read
/// (e.g., it does not exist), only extension-based detection is attempted.
///
/// # Examples
///
/// ```no_run
/// use philiprehberger_mime_detect::detect_from_path;
/// use std::path::Path;
///
/// if let Some(ft) = detect_from_path(Path::new("photo.jpg")) {
///     println!("{}", ft.mime_type());
/// }
/// ```
pub fn detect_from_path(path: &Path) -> Option<FileType> {
    // Try content-based detection first
    if let Ok(mut file) = std::fs::File::open(path) {
        let mut buf = [0u8; 512];
        if let Ok(n) = file.read(&mut buf) {
            if n > 0 {
                if let Some(ft) = detect_from_bytes(&buf[..n]) {
                    return Some(ft);
                }
            }
        }
    }

    // Fall back to extension
    let ext = path.extension()?.to_str()?;
    detect_from_extension(ext)
}

/// Detects a file type by reading up to `limit` bytes from a reader.
///
/// # Examples
///
/// ```
/// use philiprehberger_mime_detect::detect_from_reader;
/// use std::io::Cursor;
///
/// let data = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
/// let mut cursor = Cursor::new(data);
/// let ft = detect_from_reader(&mut cursor, 512).unwrap();
/// assert_eq!(ft.mime_type(), "image/png");
/// ```
pub fn detect_from_reader(reader: &mut impl Read, limit: usize) -> Option<FileType> {
    let mut buf = vec![0u8; limit];
    let n = reader.read(&mut buf).ok()?;
    if n == 0 {
        return None;
    }
    detect_from_bytes(&buf[..n])
}

/// Returns the default file extension for a MIME type.
///
/// # Examples
///
/// ```
/// use philiprehberger_mime_detect::mime_to_extension;
///
/// assert_eq!(mime_to_extension("image/png"), Some("png"));
/// ```
pub fn mime_to_extension(mime: &str) -> Option<&'static str> {
    let mime_lower = mime.to_ascii_lowercase();
    for entry in EXT_MAP {
        if entry.mime == mime_lower {
            return Some(entry.extension);
        }
    }
    None
}

/// Returns the MIME type for a file extension.
///
/// The extension can be provided with or without a leading dot, and is
/// matched case-insensitively.
///
/// # Examples
///
/// ```
/// use philiprehberger_mime_detect::extension_to_mime;
///
/// assert_eq!(extension_to_mime("html"), Some("text/html"));
/// ```
pub fn extension_to_mime(ext: &str) -> Option<&'static str> {
    let normalized = normalize_ext(ext);
    for entry in EXT_MAP {
        if entry.extension == normalized {
            return Some(entry.mime);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_jpeg() {
        let ft = detect_from_bytes(&[0xFF, 0xD8, 0xFF, 0xE0]).unwrap();
        assert_eq!(ft.mime_type(), "image/jpeg");
        assert_eq!(ft.extension(), "jpg");
        assert!(ft.is_image());
        assert_eq!(ft.kind(), FileKind::Image);
    }

    #[test]
    fn test_detect_png() {
        let ft = detect_from_bytes(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]).unwrap();
        assert_eq!(ft.mime_type(), "image/png");
        assert_eq!(ft.extension(), "png");
        assert!(ft.is_image());
    }

    #[test]
    fn test_detect_pdf() {
        let ft = detect_from_bytes(b"%PDF-1.4").unwrap();
        assert_eq!(ft.mime_type(), "application/pdf");
        assert_eq!(ft.extension(), "pdf");
        assert_eq!(ft.kind(), FileKind::Document);
    }

    #[test]
    fn test_detect_gif() {
        let ft = detect_from_bytes(b"GIF89a").unwrap();
        assert_eq!(ft.mime_type(), "image/gif");
        assert_eq!(ft.extension(), "gif");
    }

    #[test]
    fn test_detect_zip() {
        let ft = detect_from_bytes(&[0x50, 0x4B, 0x03, 0x04]).unwrap();
        assert_eq!(ft.mime_type(), "application/zip");
        assert_eq!(ft.extension(), "zip");
    }

    #[test]
    fn test_detect_webp() {
        let mut header = vec![0u8; 12];
        header[0..4].copy_from_slice(b"RIFF");
        header[4..8].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // size placeholder
        header[8..12].copy_from_slice(b"WEBP");
        let ft = detect_from_bytes(&header).unwrap();
        assert_eq!(ft.mime_type(), "image/webp");
        assert_eq!(ft.extension(), "webp");
        assert!(ft.is_image());
    }

    #[test]
    fn test_detect_wav() {
        let mut header = vec![0u8; 12];
        header[0..4].copy_from_slice(b"RIFF");
        header[4..8].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        header[8..12].copy_from_slice(b"WAVE");
        let ft = detect_from_bytes(&header).unwrap();
        assert_eq!(ft.mime_type(), "audio/wav");
        assert_eq!(ft.extension(), "wav");
        assert!(ft.is_audio());
    }

    #[test]
    fn test_extension_without_dot() {
        let ft = detect_from_extension("jpg").unwrap();
        assert_eq!(ft.mime_type(), "image/jpeg");
    }

    #[test]
    fn test_extension_with_dot() {
        let ft = detect_from_extension(".jpg").unwrap();
        assert_eq!(ft.mime_type(), "image/jpeg");
    }

    #[test]
    fn test_extension_case_insensitive() {
        let ft = detect_from_extension("JSON").unwrap();
        assert_eq!(ft.mime_type(), "application/json");

        let ft = detect_from_extension(".PDF").unwrap();
        assert_eq!(ft.mime_type(), "application/pdf");
    }

    #[test]
    fn test_mime_to_extension() {
        assert_eq!(mime_to_extension("image/png"), Some("png"));
        assert_eq!(mime_to_extension("text/html"), Some("html"));
        assert_eq!(mime_to_extension("application/json"), Some("json"));
    }

    #[test]
    fn test_extension_to_mime() {
        assert_eq!(extension_to_mime("html"), Some("text/html"));
        assert_eq!(extension_to_mime("css"), Some("text/css"));
        assert_eq!(extension_to_mime("rs"), Some("text/x-rust"));
    }

    #[test]
    fn test_unknown_bytes() {
        assert!(detect_from_bytes(&[0x01, 0x02, 0x03]).is_none());
    }

    #[test]
    fn test_unknown_extension() {
        assert!(detect_from_extension("xyz123").is_none());
    }

    #[test]
    fn test_empty_bytes() {
        assert!(detect_from_bytes(&[]).is_none());
    }

    #[test]
    fn test_filekind_is_video() {
        let ft = FileType { mime: "video/mp4", extension: "mp4", kind: FileKind::Video };
        assert!(ft.is_video());
        assert!(!ft.is_image());
        assert!(!ft.is_audio());
        assert!(!ft.is_text());
        assert!(!ft.is_archive());
    }

    #[test]
    fn test_filekind_is_text() {
        let ft = detect_from_extension("html").unwrap();
        assert!(ft.is_text());
    }

    #[test]
    fn test_filekind_is_archive() {
        let ft = detect_from_extension("zip").unwrap();
        assert!(ft.is_archive());
    }

    #[test]
    fn test_detect_elf() {
        let ft = detect_from_bytes(&[0x7F, 0x45, 0x4C, 0x46]).unwrap();
        assert_eq!(ft.mime_type(), "application/x-elf");
        assert_eq!(ft.extension(), "elf");
        assert_eq!(ft.kind(), FileKind::Executable);
    }

    #[test]
    fn test_detect_mp3_id3() {
        let ft = detect_from_bytes(b"ID3\x04\x00").unwrap();
        assert_eq!(ft.mime_type(), "audio/mpeg");
        assert_eq!(ft.extension(), "mp3");
        assert!(ft.is_audio());
    }

    #[test]
    fn test_detect_wasm() {
        let ft = detect_from_bytes(&[0x00, 0x61, 0x73, 0x6D]).unwrap();
        assert_eq!(ft.mime_type(), "application/wasm");
        assert_eq!(ft.extension(), "wasm");
        assert_eq!(ft.kind(), FileKind::Executable);
    }

    #[test]
    fn test_detect_from_reader() {
        let data = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let mut cursor = std::io::Cursor::new(data);
        let ft = detect_from_reader(&mut cursor, 512).unwrap();
        assert_eq!(ft.mime_type(), "image/png");
    }

    #[test]
    fn test_detect_avi() {
        let mut header = vec![0u8; 12];
        header[0..4].copy_from_slice(b"RIFF");
        header[4..8].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        header[8..12].copy_from_slice(b"AVI ");
        let ft = detect_from_bytes(&header).unwrap();
        assert_eq!(ft.mime_type(), "video/x-msvideo");
        assert_eq!(ft.extension(), "avi");
        assert!(ft.is_video());
    }

    #[test]
    fn test_detect_flac() {
        let ft = detect_from_bytes(b"fLaC\x00\x00").unwrap();
        assert_eq!(ft.mime_type(), "audio/flac");
    }

    #[test]
    fn test_detect_gzip() {
        let ft = detect_from_bytes(&[0x1F, 0x8B, 0x08]).unwrap();
        assert_eq!(ft.mime_type(), "application/gzip");
        assert_eq!(ft.extension(), "gz");
    }

    #[test]
    fn test_detect_avif() {
        let mut header = vec![0u8; 12];
        header[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x1C]); // size
        header[4..12].copy_from_slice(b"ftypavif");
        let ft = detect_from_bytes(&header).unwrap();
        assert_eq!(ft.mime_type(), "image/avif");
        assert_eq!(ft.extension(), "avif");
    }

    #[test]
    fn test_detect_sqlite() {
        let ft = detect_from_bytes(b"SQLite format 3\0").unwrap();
        assert_eq!(ft.mime_type(), "application/x-sqlite3");
    }

    #[test]
    fn test_detect_7z() {
        let ft = detect_from_bytes(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]).unwrap();
        assert_eq!(ft.mime_type(), "application/x-7z-compressed");
        assert_eq!(ft.extension(), "7z");
    }

    #[test]
    fn test_detect_woff2() {
        let ft = detect_from_bytes(b"wOF2").unwrap();
        assert_eq!(ft.mime_type(), "font/woff2");
        assert_eq!(ft.extension(), "woff2");
        assert_eq!(ft.kind(), FileKind::Font);
    }
}
