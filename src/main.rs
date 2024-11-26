mod ips;
mod command;
mod v2ray;
mod utils;

use crate::utils::get_user_input;
use std::io::{ self, Write };
use clipboard::{ ClipboardContext, ClipboardProvider };

static CIDR_PATH: &str = "cidr";
static EXE_CLI: &str = "resources/CloudflareST.exe"; // CLI程序
static IPS_V4_PATH: &str = "ips-v4.txt"; // IPv4 CIDR的文件
static IPS_V4_TEMP: &str = "temp.txt"; // 由CIDR生成的IP地址文件(临时)
static CSV_FILE: &str = "result.csv"; // csv优选地址
static CONFIG_FILE: &str = "resources/config.yaml"; // vless/trojan代理协议对应的yaml配置
static COUNTRY_CODES: &[&str] = &[
    "CN", "CF", "CL", "GI", "TD", "JE", "ZM", "VN", "JO", "IO", "VG", "GB", "ID", "IN", "IT", "IL", "IR", "IQ", "YE", "AM", "JM", "SY", "HU", "NZ", "NC", "SG", "HK", "GR", "EH", "ES", "UZ", "UY", "UA", "UG", "BN", "VE", "GT", "VU", "WF", "TK", "TM", "TR", "TV", "TN", "TT", "TC", "TO", "TZ", "TH", "TW", "TJ", "SO", "SB", "SR", "SD", "SZ", "SJ", "SI", "SK", "LK", "VC", "PM", "SM", "MF", "LC", "KN", "SH", "ST", "CX", "BL", "SA", "SC", "CY", "SN", "SL", "RS", "WS", "SV", "CH", "SE", "JP", "GE", "PT", "PN", "PW", "NF", "NO", "NU", "NG", "NE", "NP", "NI", "NR", "SS", "GS", "AQ", "ZA", "NA", "MX", "MZ", "MC", "MA", "MD", "MM", "FM", "PE", "BD", "MS", "MN", "VI", "AS", "UM", "US", "MR", "MU", "YT", "MQ", "MH", "ML", "MY", "MW", "MT", "MV", "IM", "MG", "RO", "RW", "LU", "RE", "LI", "LY", "LR", "LT", "LB", "LA", "LS", "LV", "CW", "CK", "KE", "HR", "KW", "CI", "KM", "CC", "KY", "QA", "CM", "ZW", "CZ", "KH", "GA", "GH", "CA", "GW", "GN", "KG", "DJ", "KI", "HN", "ME", "HM", "SX", "NL", "KR", "HT", "KZ", "GY", "GU", "GP", "CU", "GG", "GL", "GD", "CR", "CO", "CD", "CG", "GM", "FK", "CV", "FI", "FJ", "PH", "VA", "TF", "GF", "PF", "FO", "FR", "ER", "EC", "RU", "DM", "DO", "TG", "TL", "DE", "DK", "GQ", "KP", "BV", "BI", "BF", "BT", "BQ", "BW", "BZ", "BO", "BA", "PL", "PR", "IS", "BE", "BJ", "MK", "MP", "BG", "BM", "BY", "BR", "PA", "BH", "PS", "PY", "PK", "BS", "PG", "BB", "MO", "AU", "AX", "AT", "AG", "AI", "AO", "AD", "EE", "IE", "ET", "EG", "AZ", "OM", "AW", "AE", "AR", "AF", "DZ", "AL",
];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ————————————————————————————————————————————————————————————————————————————————————

    println!("选择哪个txt文件的CIDR数据扫描？");
    println!("+--------------------------------------------------------+");
    let mut names = utils::get_file_names(CIDR_PATH)?;
    let mut i = 0;
    names.iter().for_each(|name| {
        println!(" ● {i}、{CIDR_PATH}/{name}   ");
        i += 1;
    });
    names.push(IPS_V4_PATH.to_string());
    println!(" ● {i}、{IPS_V4_PATH}   ");
    println!("+--------------------------------------------------------+");
    let label = "这里输入前面对应的数字: ";
    let index = get_user_input(label, 9999999, (0..=names.len() + 1).collect());

    let select_file = names[index].clone();
    let mut country_code = "".to_string(); // 用于添加到节点的别名中
    if select_file != IPS_V4_PATH {
        let source_path = format!("{}/{}", CIDR_PATH, select_file);
        std::fs::copy(source_path, IPS_V4_PATH)?; // 执行文件复制（会覆盖目标文件）

        country_code = utils::get_country_code(COUNTRY_CODES, &select_file.to_uppercase());
    }

    // ————————————————————————————————————————————————————————————————————————————————————

    println!();

    let label = "是否测试CIDR内所有IP地址？(Y/n，默认为n)：";
    let yes_or_no: Vec<String> = vec!["Y", "N", "y", "n", ""]
        .iter()
        .map(|&s| s.to_string())
        .collect();
    let test_allip = get_user_input(label, String::new(), yes_or_no.clone());

    /*
      按照是否测试CIDR内所有IP地址作为判断依据
        - 是，则由原CloudflareST程序生成IP地址测试，
        - 否，则由本Rust代码生成指定数量的IP地址测试。
    */
    if test_allip.to_uppercase() == "Y" {
        std::fs::copy(IPS_V4_PATH, IPS_V4_TEMP)?; // 直接复制过去
        let cidrs = ips::read_cidrs_from_file(IPS_V4_TEMP).unwrap(); // 只用于计算大概要测试多少个IP地址
        let cidrs_len = cidrs.len();
        println!(
            "共 {} 个CIDR，全IP地址测试模式，约 {} * 256 = {} 个IP要测试！\n(具体数据由CloudflareST程序计算)",
            cidrs_len,
            cidrs_len,
            cidrs_len * 256
        );
    } else {
        // 由IPv4 CIDR生成IP地址
        ips::generate_and_write_ips(IPS_V4_PATH, IPS_V4_TEMP);
    }

    // ————————————————————————————————————————————————————————————————————————————————————

    // 判断后面要执行的CLI命令，所使用的文件是否为空/不存在
    if !ips::check_file_exists_and_not_empty(IPS_V4_TEMP) {
        println!("没有IP数据去执行CloudflareST.exe");
        return Ok(());
    }

    // ————————————————————————————————————————————————————————————————————————————————————

    let ports_shape =
        r"
 +-----------------------------------------------------+
 |                                                     |
 | HTTP Ports: 80, 8080, 8880, 2052, 2082, 2086, 2095  |
 |                                                     |
 | HTTPS Ports: 443, 2053, 2083, 2087, 2096, 8443      |
 |                                                     |
 +-----------------------------------------------------+
";
    println!("{}", ports_shape);
    let label = "选择哪个端口扫描：";
    let ports_vec = vec![80, 8080, 8880, 2052, 2082, 2086, 2095, 443, 2053, 2083, 2087, 2096, 8443];
    let port = get_user_input(label, 0, ports_vec).to_string();

    // ————————————————————————————————————————————————————————————————————————————————————

    let label = "是否下载测速(Y/n)：";
    let yes_or_no: Vec<String> = vec!["Y", "N", "y", "n"]
        .iter()
        .map(|&s| s.to_string())
        .collect();
    let test_speed = get_user_input(label, String::new(), yes_or_no.clone());

    if test_speed.to_uppercase() == "Y" {
        let label =
            "根据前面测试的延迟排序，继续测速，测速数量(取值范围：1~100，也是写入csv文件的IP数量)：";
        let numbers: Vec<u8> = (1..=100).collect();
        let dn: String = get_user_input(label, 0, numbers).to_string();

        println!(
            "\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
        );

        // 运行 CloudflareST
        if test_allip.to_uppercase() == "Y" {
            let _ = command::run_cloudflare_st(
                EXE_CLI,
                vec!["-f", IPS_V4_TEMP, "-o", CSV_FILE, "-tp", &port, "-dn", &dn, "-allip"]
            ).await;
        } else {
            let _ = command::run_cloudflare_st(
                EXE_CLI,
                vec!["-f", IPS_V4_TEMP, "-o", CSV_FILE, "-tp", &port, "-dn", &dn]
            ).await;
        }
    } else {
        println!(
            "\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
        );

        // 运行 CloudflareST
        if test_allip.to_uppercase() == "Y" {
            let _ = command::run_cloudflare_st(
                EXE_CLI,
                vec!["-f", IPS_V4_TEMP, "-o", CSV_FILE, "-tp", &port, "-dd", "-allip"]
            ).await;
        } else {
            let _ = command::run_cloudflare_st(
                EXE_CLI,
                vec!["-f", IPS_V4_TEMP, "-o", CSV_FILE, "-tp", &port, "-dd"]
            ).await;
        }
    }

    // ------------------------------------------------------------------------------------

    println!(
        "\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
    );

    let label = "是否构建v2ray分享链接(Y/n)：";
    let yes_build = get_user_input(label, String::new(), yes_or_no);

    if yes_build.to_uppercase() == "Y" {
        let label = "您需要多少条分享链接(取值范围：1~1000，实际不可能超过csv文件的结果数量)：";
        let numbers: Vec<usize> = (1..=1000).collect();
        let max_nodes = get_user_input(label, 0, numbers);
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
