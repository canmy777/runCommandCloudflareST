mod ips;
mod command;
mod v2ray;

use std::io::{ self, Write };
use clipboard::{ ClipboardContext, ClipboardProvider };

static EXE_CLI: &str = "resources/CloudflareST.exe"; // CLI程序
static IPS_V4_PATH: &str = "ips-v4.txt"; // IPv4 CIDR的文件
static IPS_V4_TEMP: &str = "temp.txt"; // 由CIDR生成的IP地址文件(临时)
static CSV_FILE: &str = "result.csv"; // csv优选地址
static CONFIG_FILE: &str = "resources/config.yaml"; // vless/trojan代理协议对应的yaml配置

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

    println!(
        "\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
    );

    let label = "是否构建v2ray分享链接(Y/n)：";
    let yes_build = ips::get_user_input(label, String::new(), yes_or_no);

    if yes_build.to_uppercase() == "Y" {
        let label = "您需要多少条分享链接(取值范围：1~1000，实际不可能超过csv文件的结果数量)：";
        let numbers: Vec<usize> = (1..=1000).collect();
        let max_nodes = ips::get_user_input(label, 0, numbers);
        let port_as_u16 = port.parse::<u16>().unwrap_or(443);
        let reuslts = v2ray::build_v2ray_links(
            max_nodes,
            &country_code,
            port_as_u16,
            CONFIG_FILE,
            CSV_FILE
        );

        // 在控制台中显示多少条分享链接？
        let show_links = 10;
        println!("\n共生成 {} 条节点的分享链接，前{}条链接如下：\n", reuslts.len(), show_links);
        for s in reuslts.iter().take(show_links) {
            println!("{}", s);
        }

        // 复制到剪贴板
        let mut clipboard: ClipboardContext = ClipboardProvider::new().unwrap();
        clipboard.set_contents(reuslts.join("\n").to_owned()).unwrap();

        print!(
            "\n全部链接已复制到剪切板，可以黏贴到V2rayN、NekoBox等软件中使用！按 Enter 键退出程序！"
        );
        io::stdout().flush().unwrap();
        // 等待用户输入
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let _ = input.trim().to_string();
    }

    // ------------------------------------------------------------------------------------

    // 删除已经扫描的临时IP地址文件
    let _ = std::fs::remove_file(IPS_V4_TEMP);

    Ok(())
}
