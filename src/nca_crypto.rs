//! Private AES primitives used while reading NCA sections.

use aes::Aes128;
use aes::cipher::{BlockDecrypt, KeyInit, generic_array::GenericArray};
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};
use std::io::{self, Read, Seek, SeekFrom};
use zeroize::Zeroizing;

/// Decrypts key-area slot two, which carries the section key for this profile.
pub(crate) fn decrypt_key_area_slot2(
    encrypted_key_area: &[u8],
    application_kaek: &[u8; 16],
) -> Option<Zeroizing<[u8; 16]>> {
    if encrypted_key_area.len() != 0x40 {
        return None;
    }
    let cipher = Aes128::new(GenericArray::from_slice(application_kaek));
    let mut decrypted = Zeroizing::new([0_u8; 0x40]);
    decrypted.copy_from_slice(encrypted_key_area);
    for block in decrypted.chunks_mut(16) {
        cipher.decrypt_block(GenericArray::from_mut_slice(block));
    }
    let mut section_key = Zeroizing::new([0_u8; 16]);
    section_key.copy_from_slice(&decrypted[0x20..0x30]);
    Some(section_key)
}

/// Adds a relative block number without allowing the 64-bit CTR half to wrap.
fn checked_counter_block(base_block: u64, relative_block: u64) -> Option<u64> {
    base_block.checked_add(relative_block)
}

fn checked_counter_range(
    base_block: u64,
    relative_offset: u64,
    byte_count: usize,
) -> Option<(u64, usize)> {
    let first_block = relative_offset / 16;
    let counter_block = checked_counter_block(base_block, first_block)?;
    if byte_count > 0 {
        let last_byte = relative_offset.checked_add(u64::try_from(byte_count - 1).ok()?)?;
        checked_counter_block(base_block, last_byte / 16)?;
    }
    Some((counter_block, usize::try_from(relative_offset % 16).ok()?))
}

/// Reads a bounded NCA section through its absolute-offset AES-CTR counter.
pub(crate) struct NcaCtrReader<'a, R> {
    inner: &'a mut R,
    section_start: u64,
    length: u64,
    position: u64,
    key: &'a [u8; 16],
    section_ctr: [u8; 8],
}

impl<'a, R: Read + Seek> NcaCtrReader<'a, R> {
    pub(crate) fn new(
        inner: &'a mut R,
        section_start: u64,
        length: u64,
        key: &'a [u8; 16],
        section_ctr: [u8; 8],
    ) -> Self {
        Self {
            inner,
            section_start,
            length,
            position: 0,
            key,
            section_ctr,
        }
    }

    fn counter_at(&self, relative_offset: u64, byte_count: usize) -> io::Result<([u8; 16], usize)> {
        let (block, skip) =
            checked_counter_range(self.section_start / 16, relative_offset, byte_count)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "CTR counter range"))?;
        let mut counter = [0_u8; 16];
        for (destination, source) in counter[..8].iter_mut().zip(self.section_ctr.iter().rev()) {
            *destination = *source;
        }
        counter[8..].copy_from_slice(&block.to_be_bytes());
        Ok((counter, skip))
    }
}

impl<R: Read + Seek> Read for NcaCtrReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() || self.position >= self.length {
            return Ok(0);
        }
        let count = usize::try_from((self.length - self.position).min(buffer.len() as u64))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "section read length"))?;
        let relative_offset = self.position;
        let absolute = self
            .section_start
            .checked_add(relative_offset)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "section read offset"))?;
        self.inner.seek(SeekFrom::Start(absolute))?;
        let read = self.inner.read(&mut buffer[..count])?;
        if read > 0 {
            let (counter, skip) = self.counter_at(relative_offset, read)?;
            let mut cipher = Ctr128BE::<Aes128>::new_from_slices(self.key, &counter)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "CTR key"))?;
            if skip > 0 {
                let mut skipped = Zeroizing::new([0_u8; 16]);
                cipher.apply_keystream(&mut skipped[..skip]);
            }
            cipher.apply_keystream(&mut buffer[..read]);
            self.position = self
                .position
                .checked_add(read as u64)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "section position"))?;
        }
        Ok(read)
    }
}

impl<R: Read + Seek> Seek for NcaCtrReader<'_, R> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let next = match position {
            SeekFrom::Start(value) => value,
            SeekFrom::End(value) => self
                .length
                .checked_add_signed(value)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "section seek"))?,
            SeekFrom::Current(value) => self
                .position
                .checked_add_signed(value)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "section seek"))?,
        };
        if next > self.length {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "section seek"));
        }
        self.position = next;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        NcaCtrReader, checked_counter_block, checked_counter_range, decrypt_key_area_slot2,
    };
    use aes::Aes128;
    use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
    use ctr::Ctr128BE;
    use ctr::cipher::{KeyIvInit, StreamCipher};
    use std::io::{Cursor, Read, Seek, SeekFrom};

    #[test]
    fn ctr_reader_decrypts_arbitrary_offsets_in_short_segments() {
        let key = [0x24; 16];
        let section_ctr = [1, 2, 3, 4, 5, 6, 7, 8];
        let section_start = 0x1230_u64;
        let plaintext: Vec<u8> = (0..97).map(|value| (value * 37) as u8).collect();
        let mut counter = [0_u8; 16];
        for (destination, source) in counter[..8].iter_mut().zip(section_ctr.iter().rev()) {
            *destination = *source;
        }
        counter[8..].copy_from_slice(&(section_start / 16).to_be_bytes());
        let mut ciphertext = plaintext.clone();
        Ctr128BE::<Aes128>::new_from_slices(&key, &counter)
            .expect("valid key and counter")
            .apply_keystream(&mut ciphertext);

        let mut backing = vec![0; section_start as usize + ciphertext.len()];
        backing[section_start as usize..].copy_from_slice(&ciphertext);
        let mut source = Cursor::new(backing);
        let mut reader = NcaCtrReader::new(
            &mut source,
            section_start,
            plaintext.len() as u64,
            &key,
            section_ctr,
        );

        for (offset, length) in [(1, 11), (15, 19), (34, 7), (63, 21), (91, 6)] {
            reader
                .seek(SeekFrom::Start(offset))
                .expect("seek within section");
            let mut actual = vec![0; length];
            reader.read_exact(&mut actual).expect("read section bytes");
            let offset = usize::try_from(offset).expect("fixture offset fits usize");
            assert_eq!(actual, plaintext[offset..offset + length]);
        }
    }

    #[test]
    fn counter_uses_reversed_section_prefix_and_absolute_block_index() {
        let mut parent = Cursor::new(vec![0; 0x1000]);
        let key = [0x24; 16];
        let section_ctr = [1, 2, 3, 4, 5, 6, 7, 8];
        let reader = NcaCtrReader::new(&mut parent, 0xc00, 0x100, &key, section_ctr);
        let (counter, skipped) = reader.counter_at(31, 1).expect("CTR counter");
        assert_eq!(counter[..8], [8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(counter[8..], 0xc1_u64.to_be_bytes());
        assert_eq!(skipped, 15);
    }

    #[test]
    fn counter_block_addition_rejects_low_counter_wrap() {
        assert_eq!(checked_counter_block(u64::MAX - 2, 2), Some(u64::MAX));
        assert_eq!(checked_counter_block(u64::MAX, 1), None);
        assert!(checked_counter_range(u64::MAX, 0, 17).is_none());
    }

    #[test]
    fn key_area_decryption_selects_the_application_section_slot() {
        let kaek = [0x24; 16];
        let cipher = Aes128::new(GenericArray::from_slice(&kaek));
        let mut encrypted = [0_u8; 0x40];
        for (slot, block) in encrypted.as_chunks_mut::<16>().0.iter_mut().enumerate() {
            block.fill(0x10 + slot as u8);
            cipher.encrypt_block(GenericArray::from_mut_slice(block));
        }

        let key = decrypt_key_area_slot2(&encrypted, &kaek).expect("valid key-area length");
        assert_eq!(&*key, &[0x12; 16]);
    }
}
