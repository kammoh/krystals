use rand::RngCore;
use std::collections::VecDeque;

#[derive(Default)]
pub struct BufferRng {
    buffer: VecDeque<u8>,
}

impl BufferRng {
    pub fn load_bytes(&mut self, bytes: &[u8]) {
        self.buffer.extend(bytes);
    }
    pub fn reset(&mut self) {
        self.buffer.clear();
    }
}

impl RngCore for BufferRng {
    fn next_u32(&mut self) -> u32 {
        todo!()
    }

    fn next_u64(&mut self) -> u64 {
        todo!()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest).unwrap();
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        for d in dest {
            match self.buffer.pop_front() {
                Some(x) => *d = x,
                _ => return Err(rand::Error::new("Not enough bytes in the buffer!")),
            }
        }
        Ok(())
    }
}
