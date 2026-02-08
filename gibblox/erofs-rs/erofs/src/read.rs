use core::convert::TryInto;

use alloc::string::String;

use crate::{Error, Result};

pub struct ReadCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ReadCursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_bytes<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self.pos.saturating_add(N);
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| Error::OutOfBounds(String::from("failed to read bytes from image")))?;
        self.pos = end;
        slice
            .try_into()
            .map_err(|_| Error::OutOfBounds(String::from("failed to read bytes from image")))
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        Ok(self.read_bytes::<1>()?[0])
    }

    pub fn read_u16_le(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.read_bytes::<2>()?))
    }

    pub fn read_u32_le(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.read_bytes::<4>()?))
    }

    pub fn read_u64_le(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.read_bytes::<8>()?))
    }

    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.read_bytes::<N>()
    }
}
