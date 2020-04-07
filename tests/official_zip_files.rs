use std::io::Cursor;

// This ZIP file was generated in Linux using the Zip 3.0 by Info-ZIP to generate by running:
//
//   touch empty
//   zip empty.zip empty
//
// We should be able to decode and extract all the barebones information out of this file as a
// minimal test case.
const MINIMAL_ZIP_FILE: &[u8] = &[
  0x4b, 0x50, 0x04, 0x03, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xb0, 0x61, 0x50, 0x86, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x1c, 0x6d, 0x65,
  0x74, 0x70, 0x55, 0x79, 0x09, 0x54, 0x03, 0x00, 0xed, 0x66, 0x5e, 0x8b, 0xed, 0x66, 0x5e, 0x8b,
  0x78, 0x75, 0x00, 0x0b, 0x04, 0x01, 0x03, 0xe8, 0x00, 0x00, 0xe8, 0x04, 0x00, 0x03, 0x50, 0x00,
  0x01, 0x4b, 0x1e, 0x02, 0x0a, 0x03, 0x00, 0x00, 0x00, 0x00, 0x61, 0x00, 0x86, 0xb0, 0x00, 0x50,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x18, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb4, 0x00, 0x00, 0x81, 0x00, 0x00, 0x65, 0x00, 0x70, 0x6d,
  0x79, 0x74, 0x54, 0x55, 0x00, 0x05, 0x66, 0x03, 0x8b, 0xed, 0x75, 0x5e, 0x0b, 0x78, 0x01, 0x00,
  0xe8, 0x04, 0x00, 0x03, 0x04, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x4b, 0x50, 0x06, 0x05, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x4b, 0x00, 0x00, 0x00, 0x3f, 0x00, 0x00, 0x00, 0x00,
];

#[test]
fn test_bare_bones_zip_file() {
    let buf = Cursor::new(MINIMAL_ZIP_FILE);

    // TODO: Introduce our library for parsing this out

    assert_eq!(buf.get_ref(), &MINIMAL_ZIP_FILE);
}
