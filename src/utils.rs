use std::error::Error;
use std::io::Read;

pub fn read_varint<R: Read>(reader: &mut R) -> Result<u64, Box<dyn Error>> {
    let mut buffer = [0u8; 1];
    reader.read_exact(&mut buffer)?;

    match buffer[0] {
        0..=252 => Ok(buffer[0] as u64), // 1 byte varint
        0xFD => {
            let mut buffer = [0u8; 2]; // 2 bytes for 0xFD varint
            reader.read_exact(&mut buffer)?;
            Ok(u16::from_le_bytes(buffer) as u64) // 16-bit varint
        }
        0xFE => {
            let mut buffer = [0u8; 4]; // 4 bytes for 0xFE varint
            reader.read_exact(&mut buffer)?;
            Ok(u32::from_le_bytes(buffer) as u64) // 32-bit varint
        }
        0xFF => {
            let mut buffer = [0u8; 8]; // 8 bytes for 0xFF varint
            reader.read_exact(&mut buffer)?;
            Ok(u64::from_le_bytes(buffer)) // 64-bit varint
        }
    }
}
