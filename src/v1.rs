mod ips;
mod command;
mod v2ray;
mod utils;

use crate::utils::get_user_input;

static CIDR_PATH: &str = "cidr";
static EXE_CLI: &str = "resources/CloudflareST.exe"; // CLI程序
static IPS_V4_PATH: &str = "ips-v4.txt"; // IPv4 CIDR的文件
static IPS_V4_TEMP: &str = "temp.txt"; // 由CIDR生成的IP地址文件(临时)
static CSV_FILE: &str = "result.csv"; // csv优选地址

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
    if select_file != IPS_V4_PATH {
        let source_path = format!("{}/{}", CIDR_PATH, select_file);
        std::fs::copy(source_path, IPS_V4_PATH)?; // 执行文件复制（会覆盖目标文件）
    }

    // ————————————————————————————————————————————————————————————————————————————————————

    println!();

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
