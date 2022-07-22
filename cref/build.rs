use glob::glob;

use std::{
    env,
    path::{Path, PathBuf},
};

use cargo_emit::{rerun_if_changed, rustc_link_lib, rustc_link_search};

trait Algorithm {
    fn alg_name(&self) -> &'static str;

    fn variant_name(&self, level: u8) -> &'static str;

    fn sec_param_value(&self, level: u8) -> u8 {
        level
    }

    fn ref_path(&self) -> PathBuf {
        Path::new(format!("{}/ref", self.alg_name()).as_str()).to_path_buf()
    }

    fn sec_param_name(&self) -> &'static str;
}

struct Kyber;

impl Algorithm for Kyber {
    fn alg_name(&self) -> &'static str {
        "kyber"
    }

    fn variant_name(&self, level: u8) -> &'static str {
        match level {
            1 => "kyber512",
            3 => "kyber768",
            5 => "kyber1024",
            _ => unreachable!(),
        }
    }

    fn sec_param_value(&self, level: u8) -> u8 {
        match level {
            1 => 2,
            3 => 3,
            5 => 4,
            _ => unreachable!(),
        }
    }

    fn sec_param_name(&self) -> &'static str {
        "KYBER_K"
    }
}
struct Dilithium;

impl Algorithm for Dilithium {
    fn alg_name(&self) -> &'static str {
        "dilithium"
    }

    fn variant_name(&self, level: u8) -> &'static str {
        match level {
            2 => "dilithium2",
            3 => "dilithium3",
            5 => "dilithium5",
            _ => unreachable!(),
        }
    }

    fn sec_param_name(&self) -> &'static str {
        "DILITHIUM_MODE"
    }
}

fn compile_lib(alg: &dyn Algorithm, level: u8) {
    let ref_dir = alg.ref_path();
    rerun_if_changed!(ref_dir.to_str().unwrap());

    let symbol_map = [
        // "ntt", "invntt", "basemul", "poly_ntt", "poly_invntt_tomont"
        ]
    .map(|s| {
        (
            format!("pqcrystals_{}_ref_{}", alg.variant_name(level), s),
            s,
        )
    });

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    let mut bindings_builder = bindgen::builder()
        .clang_arg(format!("-I{}", ref_dir.to_string_lossy()))
        .clang_arg(format!(
            "-D{}={}",
            alg.sec_param_name(),
            alg.sec_param_value(level)
        ));

    for (symbol, name) in &symbol_map {
        bindings_builder = bindings_builder.clang_arg(format!("-D{symbol}={name}"))
    }

    for header in glob(format!("{}/**/*.h", ref_dir.to_string_lossy()).as_str())
        .unwrap()
        .map(|p| p.unwrap())
    {
        let file_name = header.file_name().unwrap().to_str().unwrap();
        if ["rng.h", "cpucycles.h"].contains(&file_name) {
            continue;
        }
        bindings_builder = bindings_builder.header(header.to_string_lossy());
    }

    bindings_builder
        .size_t_is_usize(true)
        .allowlist_function("pqcrystals_.*")
        .allowlist_var("[A-Z0-9_]+") // constants
        .ctypes_prefix("cty")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .derive_default(false)
        .generate()
        .expect("bindgen failed")
        .write_to_file(out_path.join(format!("{}_bindings.rs", alg.variant_name(level))))
        .expect("Couldn't write bindings!");

    let mut cc_build = cc::Build::new();

    fn exclude_path(path: &PathBuf) -> bool {
        let file_name = path.file_name().unwrap().to_str().unwrap();
        !file_name.contains("test")
            && !file_name.contains("genKAT")
            && !["rng.c", "cpucycles.c", "speed_print.c", "test_speed.c"].contains(&file_name)
    }

    let c_files = glob(format!("{}/**/*.c", ref_dir.to_string_lossy()).as_str())
        .unwrap()
        .filter_map(|p| p.ok().filter(exclude_path));

    cc_build
        .files(c_files)
        .include(ref_dir)
        .out_dir(&out_path)
        .opt_level(3)
        // .flag("-O3")
        .force_frame_pointer(false)
        // .flag("-fomit-frame-pointer")
        .flag_if_supported("-march=native")
        .flag_if_supported("-mtune=native")
        .debug(false)
        // .flag("-g0")
        .define(
            alg.sec_param_name(),
            Some(alg.sec_param_value(level).to_string().as_str()),
        );

    for (sym, repl) in symbol_map {
        cc_build.define(&sym, Some(repl));
    }

    let lib_name = format!("{}", alg.variant_name(level));

    cc_build.compile(format!("lib{lib_name}.a").as_str());

    rustc_link_lib!(
        lib_name => "static"
    );

    rustc_link_search!(
        out_path.to_str().unwrap() => "native"
    );
}

fn main() {
    for level in [1, 3, 5] {
        compile_lib(&Kyber, level);
    }

    for level in [2, 3, 5] {
        compile_lib(&Dilithium, level);
    }
}
