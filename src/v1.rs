mod ips;
mod command;

static EXE_CLI: &str = "resources/CloudflareST.exe"; // CLI程序
static IPS_V4_PATH: &str = "ips-v4.txt"; // IPv4 CIDR的文件
static IPS_V4_TEMP: &str = "temp.txt"; // 由CIDR生成的IP地址文件(临时)
static CSV_FILE: &str = "result.csv"; // csv优选地址

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ————————————————————————————————————————————————————————————————————————————————————
    let code_shape =
        r"
    +----------------------------------------------------+
    |                                                    |
    |   US：美国的CIDR，GB：英国的CIDR，HK：香港的CIDR   |
    |            ALL: 全部国家/地区（不区分）            |
    |     直接按Enter键，就使用ips-v4.txt文件的CIDR      |
    |                                                    |
    +----------------------------------------------------+
";
    println!("{}", code_shape);
    let mut country_code = String::new();
    let code_vec = vec!["US", "HK", "GB", "ALL", ""];
    // 将 Vec<&str> 转换为 Vec<String>
    let country_code_vec: Vec<String> = code_vec
        .iter()
        .map(|&s| s.to_string())
        .collect();

    let label = "选择哪个国家/地区的CIDR扫描: ";
    country_code = ips::get_user_input(label, country_code, country_code_vec);

    if country_code != "" {
        let source_path = format!("./cidr/v4_{}.txt", country_code);

        // 执行文件复制（会覆盖目标文件）
        std::fs::copy(source_path, IPS_V4_PATH)?;
    }

    // ————————————————————————————————————————————————————————————————————————————————————

    // 由IPv4 CIDR生成IP地址
    ips::generate_and_write_ips(IPS_V4_PATH, IPS_V4_TEMP);

    // 判断后面要执行的CLI命令，所使用的文件是否为空/不存在
    if !ips::check_file_exists_and_not_empty(IPS_V4_TEMP) {
        println!("没有IP数据去执行CloudflareST.exe");
        return Ok(());
    }

    // ————————————————————————————————————————————————————————————————————————————————————
    let ports_shape =
        r"
    +----------------------------------------------------+
    |                                                    |
    | HTTP Ports: 80, 8080, 8880, 2052, 2082, 2086, 2095 |
    |                                                    |
    | HTTPS Ports: 443, 2053, 2083, 2087, 2096, 8443     |
    |                                                    |
    +----------------------------------------------------+
";
    println!("{}", ports_shape);
    let label = "选择哪个端口扫描：";
    let ports_vec = vec![80, 8080, 8880, 2052, 2082, 2086, 2095, 443, 2053, 2083, 2087, 2096, 8443];
    let port = ips::get_user_input(label, 0, ports_vec).to_string();

    println!("您选择的端口：{}\n", port);

    // ————————————————————————————————————————————————————————————————————————————————————

    let label = "是否下载测速(Y/n)：";
    let yes_or_no: Vec<String> = vec!["Y", "N", "y", "n"]
        .iter()
        .map(|&s| s.to_string())
        .collect();
    let test_speed = ips::get_user_input(label, String::new(), yes_or_no.clone());

    if test_speed.to_uppercase() == "Y" {
        let label =
            "根据前面测试的延迟排序，继续测速，测速数量(取值范围：1~100，也是写入csv文件的IP数量)：";
        let numbers: Vec<u8> = (1..=100).collect();
        let dn: String = ips::get_user_input(label, 0, numbers).to_string();

        println!(
            "\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
        );

        // 运行 CloudflareST
        let _ = command::run_cloudflare_st(
            EXE_CLI,
            vec!["-f", IPS_V4_TEMP, "-o", CSV_FILE, "-tp", &port, "-dn", &dn]
        ).await;
    } else {
        println!(
            "\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
        );

        // 运行 CloudflareST
        let _ = command::run_cloudflare_st(
            EXE_CLI,
            vec!["-f", IPS_V4_TEMP, "-o", CSV_FILE, "-tp", &port, "-dd"]
        ).await;
    }

    // ------------------------------------------------------------------------------------

    // 删除已经扫描的临时IP地址文件
    let _ = std::fs::remove_file(IPS_V4_TEMP);

    Ok(())
}
