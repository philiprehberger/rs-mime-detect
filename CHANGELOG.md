# Changelog

## 0.3.0 (2026-04-27)

- Add `FileType::is_document()`, `is_font()`, and `is_executable()` for category checks parallel to existing `is_image`/`is_video`/`is_audio`/`is_text`/`is_archive`
- Add `all_extensions_for_mime(mime)` returning every known extension for a MIME type (e.g. `image/jpeg` ⇒ `jpg` and `jpeg`)
- Standardize CHANGELOG entry format to `## X.Y.Z (YYYY-MM-DD)`

## 0.2.0 (2026-04-05)

- Add `detect_from_filename` function for detecting file type from a full filename string

## 0.1.2 (2026-03-31)

- Standardize README to 3-badge format with emoji Support section
- Update CI checkout action to v5 for Node.js 24 compatibility

## 0.1.1 (2026-03-27)

- Add GitHub issue templates, PR template, and dependabot configuration
- Update README badges and add Support section

## 0.1.0 (2026-03-19)

- Initial release
- Detect file type from content bytes (magic number matching)
- Detect file type from file extension
- Combined detection (content priority, extension fallback)
- 100+ supported file types across images, video, audio, documents, archives, fonts
- MIME type to extension and extension to MIME type mapping
- FileKind categorization (Image, Video, Audio, Document, Archive, Font, Executable, Other)
- Streaming detection from reader
