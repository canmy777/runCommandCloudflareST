use std::fs;
use std::io;

fn get_file_names(dir_path: &str) -> io::Result<Vec<String>> {
    let names: Vec<String> = fs
        ::read_dir(dir_path)?
        .filter_map(|entry| {
            entry.ok().and_then(|e| {
                let path = e.path();
                if path.is_file() && path.extension()?.to_str()? == "txt" {
                    path.file_name()?
                        .to_str()
                        .map(|s| s.to_string())
                } else {
                    None
                }
            })
        })
        .collect();

    Ok(names)
}

fn main() -> io::Result<()> {
    let dir_path = "cidr";

    let names = get_file_names(dir_path)?;

    for name in names {
        println!("{}", name);
    }

    Ok(())
}
