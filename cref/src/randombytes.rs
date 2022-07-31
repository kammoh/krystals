#![cfg_attr(not(any(feature = "std", not(test))), no_std)]

use core::cell::RefCell;

use ringbuffer::{ConstGenericRingBuffer, RingBufferRead, RingBufferWrite};

type RingBufferRng = ConstGenericRingBuffer<u8, 128>;

#[cfg(feature = "std")]
thread_local! {
    static RING_BUFFER: RefCell<RingBufferRng> = RefCell::new(RingBufferRng::new());
}

#[no_mangle]
pub extern "C" fn randombytes(out: *mut u8, outlen: usize) {
    let out = unsafe { core::slice::from_raw_parts_mut(out, outlen) };
    randombytes_from_queue(out);
}

fn push_bytes(ring_buffer: &mut RingBufferRng, bytes: &[u8]) {
    for byte in bytes {
        ring_buffer.push(*byte); // hangs if capacity has reached
    }
}

pub fn randombytes_push_to_queue(bytes: &[u8]) {
    #[cfg(feature = "std")]
    RING_BUFFER.with(|ring_buffer| {
        push_bytes(&mut ring_buffer.borrow_mut(), bytes);
    });
}

pub fn randombytes_from_queue(out: &mut [u8]) {
    #[cfg(feature = "std")]
    RING_BUFFER.with(|ring_buffer| {
        let rb = &mut ring_buffer.borrow_mut();
        for byte in out {
            *byte = rb.dequeue().expect("Not enough bytes in RING_BUFFER.");
        }
    });
}
