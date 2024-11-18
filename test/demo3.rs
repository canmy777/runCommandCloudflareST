use csv::ReaderBuilder;
use serde::Deserialize;
use std::error::Error;

#[derive(Debug, Deserialize)]
struct Record {
    #[serde(rename = "IP 地址")]
    ip1: Option<String>,

    #[serde(rename = "IP地址")]
    ip2: Option<String>,

    #[serde(rename = "端口")]
    port: Option<u16>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let file_path = "result.csv";

    // 创建CSV阅读器
    let mut rdr = ReaderBuilder::new()
        .has_headers(true) // 如果文件包含头部，则设置为 true
        .from_path(file_path)?;

    let max_numbers: usize = 100;
    let mut count = 0;

    // 迭代每一行记录
    for result in rdr.deserialize() {
        let record: Record = result?;

        // 打印你想要的列内容，这里以 alias1 和 alias2 为例
        let ip_address = match &record.ip1 {
            Some(value) => value,
            None => { record.ip2.as_ref().map_or("", |v| v) }
        };
        println!("IP: {}", ip_address);

        let port = match &record.port {
            Some(value) => value,
            None => &443,
        };
        println!("Port: {}", port);

        count += 1;

        if count >= max_numbers {
            break;
        }
    }

    Ok(())
}
