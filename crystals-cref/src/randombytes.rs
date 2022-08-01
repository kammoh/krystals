#![cfg_attr(not(any(feature = "std", not(test))), no_std)]

use core::cell::RefCell;

use ringbuffer::{ConstGenericRingBuffer, RingBufferRead, RingBufferWrite};

type RingBufferRng = ConstGenericRingBuffer<u8, 128>;

#[cfg(all(feature = "std", feature = "randombytes"))]
thread_local! {
    static RING_BUFFER: RefCell<RingBufferRng> = RefCell::new(RingBufferRng::new());
}

#[no_mangle]
pub extern "C" fn randombytes(out: *mut u8, outlen: usize) {
    // UNSAFE! We have no idea what we're receiving from C!
    let out = unsafe { core::slice::from_raw_parts_mut(out, outlen) };
    get_random_bytes(out);
}

pub fn randombytes_push_bytes(bytes: &[u8]) {
    #[cfg(all(feature = "std", feature = "randombytes"))]
    RING_BUFFER.with(|ring_buffer| {
        let rb = &mut ring_buffer.borrow_mut();
        for byte in bytes {
            rb.push(*byte); // hangs if capacity has reached
        }
    });

    #[cfg(not(all(feature = "std", feature = "randombytes")))]
    { /* */ }
    // panic!("randombytes_push_to_queue should not be called if randombytes feature is not enabled");
}

#[cfg(all(feature = "std", feature = "randombytes"))]
fn get_random_bytes(out: &mut [u8]) {
    RING_BUFFER.with(|ring_buffer| {
        let rb = &mut ring_buffer.borrow_mut();
        #[cfg(test)]
        for byte in out {
            *byte = rb.dequeue().expect("Not enough bytes in RING_BUFFER.");
        }
        #[cfg(not(test))] // fast output for benchmark of the C reference code
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = rb.dequeue().unwrap_or((i * 119 + 0xA5) as u8);
        }
    });
}

#[cfg(not(all(feature = "std", feature = "randombytes")))]
fn get_random_bytes(out: &mut [u8]) {
    // #[inline(always)]
    // pub fn lehmer64(state: &u64) {
    //     *state = state.wrapping_mul(0xda942042e4dd58b5).wrapping_shr(64);
    // }
    // let mut lehmer64_state = 999999999;

    for (i, byte) in out.iter_mut().enumerate() {
        // lehmer64(lehmer64_state);
        // *byte = lehmer64_state as u8;
        *byte = i as u8;
    }
}

// #[cfg(all(feature = "std", not(feature = "randombytes")))]
// fn get_random_bytes(out: &mut [u8]) {}

// #[cfg(all(not(feature = "std")))]
// fn get_random_bytes(out: &mut [u8]) {}
