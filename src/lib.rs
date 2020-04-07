//! A pure rust implementation for reading ZIP archives.

// #![warn(missing_docs)]

pub const ARCHIVE_EXTRA_DATA_SIGNATURE: u32 = 0x08064b50;

// This is commonly adopted as the signature value for the data descriptor record, but this is
// optional and zip files may be encountered with or without this signature marking data
// descriptors.
pub const DATA_DESCRIPTOR_SIGNATURE: u32 = 0x08074b50;

pub const LOCAL_FILE_HEADER_SIGNATURE: u32 = 0x04034b50;

// * All values must be stored in little-endian byte order, specifically in low-byte:high-byte,
//   low-word:high-word order.
// * String fields are not null terminated since lengths are explicit
// * Entries in the central directory don't have to match the order of the files
// * If one of the fields in the end of central directory record is too small, the field should be
//   set to 0xffff or 0xffffffff and the zip64 format record should be created.
// * The end of central directory record and the zip64 end of central directory locator record must
//   reside on the same disk when splitting or spanning an archive

// This has the exact same format as the EncryptionHeader
pub struct ArchiveDecryptionHeader;

// This is always prefixed with the ARCHIVE_EXTRA_DATA_SIGNATURE
pub struct ArchiveExtraDataRecord {
    pub extra_field_length: u32,
    pub extra_field_data: Vec<u8>,
}

pub enum Features {
    // Referred to as the "Default" value, this is the minimum feature set required to be
    // implemented
    Minimum,
    VolumeLabel,
    Directories,
    DeflateCompression,
    PKWareEncryption,
    Deflate64Compression,
    PKWareDCLImplode,
    PatchDataSet,
    ZIP64Format,
    BZip2Compression,
    DESEncryption,
    ThreeDESEncryption,
    RC2Encryption,
    RC4Encryption,
    AESEncryption,
    CorrectedRC2Encryption,
    CorrectedRC264Encryption,
    NonOAEPKeyWrapping,
    CentralDirectoryEncryption,
    LZMACompression,
    PPMdCompression,
    BlowfishEncryption,
    TwofishEncryption,
}

impl Features {
    pub fn minimum_supported_version(&self) -> u16 {
        use self::Features::*;

        match *self {
            Minimum => 10,
            VolumeLabel => 11,
            Directories => 20,
            DeflateCompression => 20,
            PKWareEncryption => 20,
            Deflate64Compression =>21,
            PKWareDCLImplode => 25,
            PatchDataSet => 27,
            ZIP64Format => 45,
            BZip2Compression => 46,
            DESEncryption => 50,
            ThreeDESEncryption => 50,
            RC2Encryption => 50,
            RC4Encryption => 50,
            AESEncryption => 51,
            CorrectedRC2Encryption => 51,
            CorrectedRC264Encryption => 52,
            NonOAEPKeyWrapping => 61,
            CentralDirectoryEncryption => 62,
            LZMACompression => 63,
            PPMdCompression => 63,
            BlowfishEncryption => 63,
            TwofishEncryption => 63,
        }
    }
}

pub enum AttributeCompatibility {
    // MS-DOS and OS/2 (FAT / VFAT / FAT32 file systems)
    MSDOS = 0,
    Amiga = 1,
    OpenVMS = 2,
    Unix = 3,
    VMCMS = 4,
    AtariST = 5,
    OS2HPFS = 6,
    Macintosh = 7,
    ZSystem = 8,
    CPM = 9,
    WindowsNTFS = 10,
    MVS = 11,
    VSE = 12,
    AcornRisc = 13,
    VFAT = 14,
    AlternateMVS = 15,
    BeOS = 16,
    Tandem = 17,
    OS400 = 18,
    OSXDarwin = 19,

    // Technically all values 20-255, but we'll map them all here
    Unknown = 255,
}

pub struct CentralDirectory {
    pub headers: Vec<CentralDirectoryHeader>,
    pub signaure: CentralDirectorySignature,
}

pub struct CentralDirectorySignature {
    // Should be 0x05054b50
    pub signature: u32,
    pub size_of_data: u16,

    pub signature_data: Vec<u8>,
}

pub struct CentralDirectoryHeader {
    // Always set to 0x02014b50
    pub central_file_header_signature: u32,

    pub version_made_by: VersionMadeBy,
    pub version_needed_to_extract: u16,

    pub general_purpose_bit_flag: u16,
    pub compression_method: u16,

    pub last_mod_file_time: u16,
    pub last_mod_file_date: u16,

    pub crc32: u32,

    pub compressed_size: u32,
    pub uncompressed_size: u32,

    pub file_name_length: u16,
    pub extra_field_length: u16,
    pub file_comment_length: u16,

    pub disk_number_start: u16,

    pub internal_file_attributes: u16,
    pub external_file_attributes: u32,
    pub relative_offset_of_local_header: u32,

    pub file_name: Vec<u8>,
    pub extra_field: Vec<u8>,
    pub file_comment: Vec<u8>,
}

// This must exist if bit 3 of the general_purpose_bit_flag in the associated LocalFileHeader is
// set. It should be byte aligned following the last byte of compressed data. For ZIP64 format
// archives each of the size fields are 8 bytes long instead of 4 bytes. I'll need to handle that
// somehow. This size differencing bit is defined in section 4.3.9 of the app note and I should
// read it again when I'm implementing this.
//
// I couldn't tell, but when reading this it seems like it may be immediately preceded by the
// signature value mentioned.
pub struct DataDescriptor {
    pub crc32: u32,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
}

pub struct EncryptionHeader;

pub struct EndOfCentralDirectoryRecord {
    // Always set to 0x06054b50
    pub signature: u32,

    pub number_of_this_disk: u16,
    pub number_of_the_disk_with_the_start_of_the_central_directory: u16,
    pub total_number_of_entries_in_the_central_directory_on_this_disk: u16,
    pub total_number_of_entries_in_the_central_directory: u16,

    pub size_of_the_central_directory: u32,
    pub offset_of_start_of_central_directory_with_respect_to_the_starting_disk_number: u32,
    pub zip_file_comment_length: u16,
    pub zip_file_comment: Vec<u8>,
}

pub struct FileData;

pub struct LocalFileHeader {
    pub extraction_version: u16,
    pub general_purpose_bit_flag: u16,
    pub compression_method: u16,
    pub mod_file_time: u16,
    pub mod_file_date: u16,
    pub crc32: u32,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub file_name_length: u16,
    pub extra_field_length: u16,

    pub file_name: Vec<u8>,
    pub extra_field: Vec<u8>,
}

pub struct VersionMadeBy {
    pub attribute_compatibility: AttributeCompatibility,
    pub zip_specification_version: ZipSpecificationVersion,
}

// From the u16 version: major = value / 10, minor = value % 10
pub struct ZipSpecificationVersion {
    pub major: u8,
    pub minor: u8,
}

pub struct Zip64EndOfCentralDirectoryLocator {
    // Always set to 0x07064b50
    pub signature: u32,

    pub number_of_the_disk_with_the_start_of_the_zip64_end_of_central_directory: u32,
    pub relative_offset_of_the_zip64_end_of_central_directory_record: u64,
    pub total_number_of_disks: u32,
}

pub struct Zip64EndOfCentralDirectoryRecord {
    // Always set to 0x06064b50
    pub signature: u32,

    // Should be the size of this struct without the signature or this field
    pub size_of_end_of_central_directory_record: u64,

    pub version_made_by: VersionMadeBy,
    pub version_needed_to_extract: u16,

    pub number_of_this_disk: u32,
    pub number_of_the_disk_with_the_start_of_the_central_directory: u32,
    pub total_number_of_entries_in_the_central_directory_on_this_disk: u64,
    pub total_number_of_entries_in_the_central_directory: u64,
    pub size_of_the_central_directory: u64,
    pub offset_of_start_of_central_directory_with_respect_to_the_starting_disk_number: u64,

    pub zip64_extensible_data_sector: Vec<Zip64ExtensibleDataSector>,
}

pub struct Zip64ExtensibleDataSector {
    // Valid header IDs are specified in APPENDIX C of the APPNOTE
    pub header_id: u16,
    pub data_size: u32,
    pub data: Vec<u8>,
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
