#[cfg(all(test))]
#[macro_export]
#[cfg(all(test))]
macro_rules! debug {
    ($($arg:tt)*) => {{
        #[cfg(not(feature = "std"))]
        extern crate std;
        std::eprintln!($($arg)*);
    }};
}
#[macro_export]
#[cfg(not(all(test)))]
macro_rules! debug {
    ($($arg:tt)*) => {{}};
}

// from: https://github.com/wcampbell0x2a/assert_hex/blob/master/src/lib.rs
#[macro_export]
macro_rules! assert_eq_hex {
    ($left:expr, $right:expr $(,)?) => {{
        match (&$left, &$right) {
            (left_val, right_val) => {
                if !(*left_val == *right_val) {
                    // The reborrows below are intentional. Without them, the stack slot for the
                    // borrow is initialized even before the values are compared, leading to a
                    // noticeable slow down.
                    panic!(
                        r#"assertion failed: `(left == right)`
  left: `{:02x?}`,
 right: `{:02x?}`"#,
                        &*left_val, &*right_val
                    )
                }
            }
        }
    }};
}
