extern crate autocfg;

fn main() {
    let ac = autocfg::new();

    ac.emit_has_type("i128");

    ac.emit_type_cfg(
        "core::slice::ArrayChunks<'static, u8, 2>",
        "has_array_chunks",
    );

    autocfg::rerun_path("build.rs");
}
