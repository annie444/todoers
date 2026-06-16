fn main() {
    println!("cargo:rerun-if-changed=db/migrations");
    println!("cargo:rerun-if-changed=build.rs");
}
