//! A pure rust implementation for reading ZIP archives.

#![warn(missing_docs)]

const LOCAL_FILE_HEADER_SIGNATURE: u32 = 0x04034b50;

// Note: All values must be stored in little-endian byte order

struct ArchiveDecryptionHeader;
struct ArchiveExtraDataRecord
struct CentralDirectoryHeader;

// This must exist if bit 3 of the general_purpose_bit_flag in the associated LocalFileHeader is
// set. It should be byte aligned following the last byte of compressed data. For ZIP64 format
// archives each of the size fields are 8 bytes long instead of 4 bytes. I'll need to handle that
// somehow. This size differencing bit is defined in section 4.3.9 of the app note and I should
// read it again when I'm implementing this.
struct DataDescriptor {
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
}

struct EncryptionHeader;
struct EndOfCentralDirectoryRecord;
struct FileData;

struct LocalFileHeader {
    extraction_version: u16,
    general_purpose_bit_flag: u16,
    compression_method: u16,
    mod_file_time: u16,
    mod_file_date: u16,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    file_name_length: u16,
    extra_field_length: u16,

    file_name: Vec<u8>,
    extra_field: Vec<u8>,
}

struct Zip64EndOfCentralDirectoryLocator;
struct Zip64EndOfCentralDirectoryRecord;

// * The aggregate of all CentralDirectoryHeaders may be compressed
// * Each local file header must be accompanied by a corresponding
//   CentralDirectoryHeader.
// * Directories and empty files must not include FileData

// Ultimate file structure:
//
// [
//   LocalFileHeader,
//   (EncryptionHeader?, FileData, DataDescriptor?)?,
// ]*
// (
//   ArchiveDecryptionHeader,
//   ArchiveExtraDataRecord,
//   [
//     CentralDirectoryHeader,
//   ]*
//   Zip64EndOfCentralDirectoryRecord,
//   Zip64EndOfCentralDirectoryLocator,
//   EndOfCentralDirectoryRecord,
// )
