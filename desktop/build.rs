fn main() {
    println!("cargo:rerun-if-changed=../wardr/static/wardr-mark.png");
    println!("cargo:rerun-if-changed=../packaging/windows/wardr.ico");

    #[cfg(target_os = "windows")]
    {
        let mut res = winres::WindowsResource::new();
        res.set_icon("../packaging/windows/wardr.ico");
        res.set("ProductName", "Wardr");
        res.set("FileDescription", "Wardr — Local Security Monitor");
        res.set("CompanyName", "Luminary Analytics");
        res.set("LegalCopyright", "Copyright (c) Luminary Analytics");
        if let Err(err) = res.compile() {
            panic!("Failed to embed Windows application resources: {err}");
        }
    }
}
