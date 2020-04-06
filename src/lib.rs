//! A pure rust implementation for reading ZIP archives.

#![warn(missing_docs)]

const ARCHIVE_EXTRA_DATA_SIGNATURE: u32 = 0x08064b50;

// This is commonly adopted as the signature value for the data descriptor record, but this is
// optional and zip files may be encountered with or without this signature marking data
// descriptors.
const DATA_DESCRIPTOR_SIGNATURE: u32 = 0x08074b50;

const LOCAL_FILE_HEADER_SIGNATURE: u32 = 0x04034b50;

// * All values must be stored in little-endian byte order, specifically in low-byte:high-byte,
//   low-word:high-word order.
// * String fields are not null terminated since lengths are explicit
// * Entries in the central directory don't have to match the order of the files
// * If one of the fields in the end of central directory record is too small, the field should be
//   set to 0xffff or 0xffffffff and the zip64 format record should be created.
// * The end of central directory record and the zip64 end of central directory locator record must
//   reside on the same disk when splitting or spanning an archive

// This has the exact same format as the EncryptionHeader
struct ArchiveDecryptionHeader;

// This is always prefixed with the ARCHIVE_EXTRA_DATA_SIGNATURE
struct ArchiveExtraDataRecord {
    extra_field_length: u32,
    extra_field_data: Vec<u8>,
}

struct CentralDirectory {
    headers: Vec<CentralDirectoryHeader>,
    signaure: CentralDirectorySignature,
}

struct CentralDirectorySignature {
    // Should be 0x05054b50
    signature: u32,
    size_of_data: u16,

    signature_data: Vec<u8>,
}

struct CentralDirectoryHeader {
    // Always set to 0x02014b50
    central_file_header_signature: u32,

    version_made_by: VersionMadeBy,
    version_needed_to_extract: u16,

    general_purpose_bit_flag: u16,
    compression_method: u16,

    last_mod_file_time: u16,
    last_mod_file_date: u16,

    crc32: u32,

    compressed_size: u32,
    uncompressed_size: u32,

    file_name_length: u16,
    extra_field_length: u16,
    file_comment_length: u16,

    disk_number_start: u16,

    internal_file_attributes: u16,
    external_file_attributes: u32,
    relative_offset_of_local_header: u32,

    file_name: Vec<u8>,
    extra_field: Vec<u8>,
    file_comment: Vec<u8>,
}

// This must exist if bit 3 of the general_purpose_bit_flag in the associated LocalFileHeader is
// set. It should be byte aligned following the last byte of compressed data. For ZIP64 format
// archives each of the size fields are 8 bytes long instead of 4 bytes. I'll need to handle that
// somehow. This size differencing bit is defined in section 4.3.9 of the app note and I should
// read it again when I'm implementing this.
//
// I couldn't tell, but when reading this it seems like it may be immediately preceded by the
// signature value mentioned.
struct DataDescriptor {
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
}

struct EncryptionHeader;

struct EndOfCentralDirectoryRecord {
    // Always set to 0x06054b50
    signature: u32,

    number_of_this_disk: u16,
    number_of_the_disk_with_the_start_of_the_central_directory: u16,
    total_number_of_entries_in_the_central_directory_on_this_disk: u16,
    total_number_of_entries_in_the_central_directory: u16,

    size_of_the_central_directory: u32,
    offset_of_start_of_central_directory_with_respect_to_the_starting_disk_number: u32,
    zip_file_comment_length: u16,
    zip_file_comment: Vec<u8>,
}

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

enum VersionMadeBy {
    // MS-DOS and OS/2 (FAT / VFAT / FAT32 file systems)
    MSDOS = 0,
    Amiga = 1,
    OpenVMS = 2,
    Unix = 3,
    VM_CMS = 4,
    Atari_ST = 5,
    OS2_HPFS = 6,
    Macintosh = 7,
    Z_System = 8,
    CPM = 9,
    Windows_NTFS = 10,
    MVS = 11,
    VSE = 12,
    Acorn_Risc = 13,
    VFAT = 14,
    Alternate_MVS = 15,
    BeOS = 16,
    Tandem = 17,
    OS400 = 18,
    OSX_Darwin = 19,

    // Technically all values 20-255, but we'll map them all here
    Unknown = 255,
}

struct Zip64EndOfCentralDirectoryLocator {
    // Always set to 0x07064b50
    signature: u32,

    number_of_the_disk_with_the_start_of_the_zip64_end_of_central_directory: u32,
    relative_offset_of_the_zip64_end_of_central_directory_record: u64,
    total_number_of_disks: u32,
}

struct Zip64EndOfCentralDirectoryRecord {
    // Always set to 0x06064b50
    signature: u32,

    // Should be the size of this struct without the signature or this field
    size_of_end_of_central_directory_record: u64,

    version_made_by: VersionMadeBy,
    version_needed_to_extract: u16,

    number_of_this_disk: u32,
    number_of_the_disk_with_the_start_of_the_central_directory: u32,
    total_number_of_entries_in_the_central_directory_on_this_disk: u64,
    total_number_of_entries_in_the_central_directory: u64,
    size_of_the_central_directory: u64,
    offset_of_start_of_central_directory_with_respect_to_the_starting_disk_number: u64,

    zip64_extensible_data_sector: Vec<Zip64ExtensibleDataSector>,
}

struct Zip64ExtensibleDataSector {
    // Valid header IDs are specified in APPENDIX C of the APPNOTE
    header_id: u16,
    data_size: u32,
    data: Vec<u8>,
}

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
