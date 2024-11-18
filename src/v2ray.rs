use std::{ collections::BTreeMap, fs::File, io::{ BufReader, Read }, vec };
use rand::{ seq::SliceRandom, thread_rng, Rng };
use serde_yaml::{ self, Value };
use serde_qs as qs;
use csv::ReaderBuilder;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Record {
    #[serde(rename = "IP 地址")]
    ip1: Option<String>,

    // 只有ip1的字段不存在，才使用这个字段
    #[serde(rename = "IP地址")]
    ip2: Option<String>,

    #[serde(rename = "端口")]
    port: Option<u16>,
}

pub fn build_v2ray_links(
    max_nodes: usize,
    country_code: &str,
    default_port: u16,
    config_file_path: &str,
    csv_file_path: &str
) -> Vec<String> {
    let mut data: serde_yaml::Value = yaml_config_to_json(config_file_path);

    let mut rdr = ReaderBuilder::new()
        .has_headers(true) // 如果文件包含头部，则设置为 true
        .from_path(csv_file_path)
        .expect("Failed to open CSV file");

    let mut links: Vec<String> = Vec::new();
    let mut count: usize = 0;
    if let serde_yaml::Value::Sequence(array) = &data {
        let length = array.len(); // 数组中，有多少个元素

        // 迭代每一行记录
        for result in rdr.deserialize() {
            let record: Record = result.unwrap();

            // ————————————————————————————获取配置文件中的字段——————————————————————————————————————

            let server = match &record.ip1 {
                Some(value) => value,
                None => { record.ip2.as_ref().map_or("", |v| v) }
            };

            let port = match &record.port {
                Some(value) => value,
                None => &default_port,
            };

            // ——————————————————————————获取字段值并构建v2ray分享链接———————————————————————————————

            let index: usize = generate_random_number(length);
            let remarks = format!("{country_code} | {server}:{port}"); // 别名

            let client_fingerprint: Vec<&str> = vec![
                "chrome",
                "firefox",
                "safari",
                "iOS",
                "android",
                "edge",
                "360",
                "qq"
            ];
            let random_fingerprint = client_fingerprint
                .choose(&mut thread_rng())
                .unwrap_or(&"randomized");

            let proxy_type = get_outer_key_value(&mut data[index], "type");
            let network = get_outer_key_value(&mut data[index], "network");
            let (path, host) = get_path_and_host_value(&mut data[index]);
            let sni = get_sni_or_servename_value(&mut data[index]);
            match proxy_type.as_str() {
                "vless" => {
                    let uuid = get_outer_key_value(&mut data[index], "uuid");
                    let security = get_vless_tls_value(&mut data[index]);

                    let encoding_path = urlencoding::encode(&path);
                    let encoding_remarks = urlencoding::encode(remarks.as_str());

                    let mut params = BTreeMap::new();
                    params.insert("encryption", "none");
                    params.insert("security", &security);
                    params.insert("type", &network);
                    params.insert("host", &host);
                    params.insert("path", &encoding_path);
                    params.insert("sni", &sni);
                    params.insert("fp", random_fingerprint);

                    // 过滤掉值为空的键值对，然后将数据结构序列化为Query String格式的字符串
                    let all_params_str = serialize_to_query_string(params);

                    let vless_link = format!(
                        "vless://{uuid}@{server}:{port}/?{all_params_str}&allowInsecure=1#{encoding_remarks}"
                    );
                    links.push(vless_link);
                }
                "trojan" => {
                    let password = get_outer_key_value(&mut data[index], "password");

                    let security = match host.ends_with("workers.dev") {
                        true => "none",
                        false => "tls",
                    };
                    let encoding_path = urlencoding::encode(&path);
                    let encoding_remarks = urlencoding::encode(remarks.as_str());

                    let mut params = BTreeMap::new();
                    params.insert("security", security);
                    params.insert("sni", &sni);
                    params.insert("fp", &random_fingerprint);
                    params.insert("type", &network);
                    params.insert("host", &host);
                    params.insert("path", &encoding_path);

                    // 过滤掉值为空的键值对，然后将数据结构序列化为Query String格式的字符串
                    let all_params_str = serialize_to_query_string(params);

                    let trojan_link = format!(
                        "trojan://{password}@{server}:{port}/?{all_params_str}&allowInsecure=1#{encoding_remarks}"
                    );
                    links.push(trojan_link);
                }
                _ => println!("不支持{proxy_type}类型的代理"),
            }

            // ————————————————————————————————————————————————————————————————————————————————————

            count += 1;

            if count >= max_nodes {
                break;
            }
        }
    } else {
        println!("{config_file_path}文件的数据格式不匹配！");
    }

    links
}

fn yaml_config_to_json(file_path: &str) -> serde_yaml::Value {
    let file = File::open(file_path).expect("Failed to open file");
    let mut reader = BufReader::new(file);

    let mut yaml_content = String::new();
    reader.read_to_string(&mut yaml_content).expect("Failed to read YAML");

    let json_data = serde_yaml
        ::from_str::<serde_yaml::Value>(&yaml_content)
        .expect("Failed to parse YAML");
    json_data
}

fn get_outer_key_value(yaml_value: &mut Value, key: &str) -> String {
    yaml_value
        .get(&Value::String(key.to_string()))
        .and_then(Value::as_str)
        .map_or("".to_string(), |value| value.to_string())
}

// sni字段或servername字段都视为同一个字段
fn get_sni_or_servename_value(yaml_value: &mut serde_yaml::Value) -> String {
    let sni: String = match yaml_value.get("sni").and_then(serde_yaml::Value::as_str) {
        Some(value) => value.to_string(),
        None => {
            match yaml_value.get("servername").and_then(serde_yaml::Value::as_str) {
                Some(value) => value.to_string(),
                None => "".to_string(), // 默认值，如果没有找到任何字段
            }
        }
    };
    sni
}

fn get_path_and_host_value(yaml_value: &mut Value) -> (String, String) {
    let mut path = "".to_string();
    let mut host = "".to_string();
    if let Some(opts_mapping) = yaml_value.get("ws-opts").and_then(Value::as_mapping) {
        path = opts_mapping
            .get("path")
            .and_then(Value::as_str)
            .map_or("".to_string(), |value| value.to_string());
        let host_value = if
            let Some(header_mapping) = opts_mapping.get("headers").and_then(Value::as_mapping)
        {
            match header_mapping.get("Host").and_then(Value::as_str) {
                Some(value) => value.to_string(),
                None =>
                    match header_mapping.get("host").and_then(Value::as_str) {
                        Some(value) => value.to_string(),
                        None => "".to_string(), // 默认值，如果没有找到任何字段
                    }
            }
        } else {
            "".to_string()
        };
        host = host_value.to_string();
    }
    (path, host)
}

fn get_vless_tls_value(yaml_value: &mut Value) -> String {
    let security = yaml_value
        .get("tls")
        .and_then(Value::as_bool)
        .map(|v| {
            match v {
                true => "tls".to_string(),
                false => "none".to_string(),
            }
        })
        .unwrap_or("none".to_string());

    security
}

fn serialize_to_query_string(params: BTreeMap<&str, &str>) -> String {
    let filtered_params: BTreeMap<_, _> = params
        .into_iter()
        .filter(|(_, v)| !v.is_empty())
        .collect();
    let all_params_str = qs::to_string(&filtered_params).unwrap();
    all_params_str
}

fn generate_random_number(len: usize) -> usize {
    let mut rng = rand::thread_rng();
    rng.gen_range(0..len)
}
