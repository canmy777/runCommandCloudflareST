use crate::utils::get_user_input;
use std::{
    collections::HashSet,
    fs::{ self, File },
    io::{ self, BufRead, BufWriter, Write },
    net::Ipv4Addr,
    path::Path,
};
use rand::{ seq::SliceRandom, Rng };

/// 从文件读取所有 CIDR，并返回去重后的字符串向量
pub fn read_cidrs_from_file(file_path: &str) -> io::Result<Vec<String>> {
    let mut cidr_set = HashSet::new();
    let file = File::open(file_path)?;
    for line in io::BufReader::new(file).lines() {
        let cidr = line?.trim().to_string();
        if !cidr.is_empty() {
            cidr_set.insert(cidr);
        }
    }
    Ok(cidr_set.into_iter().collect())
}

/// 从 CIDR 生成指定数量的随机且不重复的 IP 地址
fn generate_ips_from_cidr(cidr: &str, count: usize) -> Option<Vec<Ipv4Addr>> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    let base_ip: Ipv4Addr = parts[0].parse().ok()?;
    let prefix_len: u32 = parts[1].parse().ok()?;
    if prefix_len > 32 {
        return None;
    }

    let mask = u32::MAX.checked_shl(32 - prefix_len).unwrap_or(0);
    let base_ip_u32 = u32::from(base_ip);
    let start_ip = base_ip_u32 & mask;
    let end_ip = start_ip | !mask;

    let range_size = end_ip - start_ip + 1;
    if (count as u32) > range_size {
        return None; // 请求数量超过 CIDR 范围内可用 IP 数量
    }

    let mut rng = rand::thread_rng();
    let mut ip_set = HashSet::new();

    while ip_set.len() < count {
        let random_offset = rng.gen_range(0..range_size);
        let ip_u32 = start_ip + random_offset;
        ip_set.insert(Ipv4Addr::from(ip_u32));
    }

    Some(ip_set.into_iter().collect())
}

/// 读取文件，生成随机 IP 地址并写入文件
pub fn generate_and_write_ips(input_file: &str, output_file: &str) {
    let cidrs = read_cidrs_from_file(input_file).unwrap();

    let cidr_count = cidrs.len();

    let label = format!("检测到 {} 个CIDR，请输入每个CIDR要生成的IP数量(1~254)：", cidr_count);

    if cidr_count == 0 {
        println!("未检测到有效的 CIDR。");
    } else {
        let numbers: Vec<usize> = (1..=255).collect();
        // 每个 CIDR 要生成的 IP 数量
        let ip_count_per_cidr = get_user_input(&label, 0, numbers);

        let mut all_ips = Vec::new();

        // 为每个 CIDR 生成随机 IP 地址
        for cidr in cidrs {
            if let Some(ips) = generate_ips_from_cidr(&cidr, ip_count_per_cidr) {
                all_ips.extend(ips);
            }
        }

        println!("共生成 {} 个IP地址。", all_ips.len());

        // 打乱 IP 地址顺序
        let mut rng = rand::thread_rng();
        all_ips.shuffle(&mut rng);

        // 将打乱后的 IP 写入文件
        let output = File::create(output_file).unwrap();
        let mut writer = BufWriter::new(output);
        for ip in all_ips {
            writeln!(writer, "{}", ip).unwrap();
        }
    }
}

/// 检查文件是否存在或为空
pub fn check_file_exists_and_not_empty(path: &str) -> bool {
    let path = Path::new(path);

    // 检查文件是否存在且是文件
    if path.exists() && path.is_file() {
        // 获取文件的元数据
        if let Ok(metadata) = fs::metadata(path) {
            // 检查文件大小是否大于0（非空）
            return metadata.len() > 0;
        }
    }

    false
}
