use std::collections::BTreeMap;
use std::fs::File;
use std::io::{ BufReader, Read };
use rand::seq::SliceRandom;
use rand::{ thread_rng, Rng };
use serde_yaml::{ self, Value };
use serde_qs as qs;

fn main() {
    let config_path = "resources/config.yaml";
    let mut data: serde_yaml::Value = yaml_config_to_json(config_path);

    if let serde_yaml::Value::Sequence(array) = &data {
        let length = array.len();
        let index: usize = generate_random_number(length);

        let server = "104.21.203.66";
        let port = 443;
        let remarks = format!("{server}:{port}");

        // ——————————————————————————————————————————————————————————————————————————————————————

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

        let proxytype = get_outer_key_value(&mut data[index], "type");
        let network = get_outer_key_value(&mut data[index], "network");
        let (path, host) = get_path_and_host_value(&mut data[index]);
        let sni = get_sni_or_servename_value(&mut data[index]);
        match proxytype.as_str() {
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
                    "vless://{uuid}@{server}:{port}/?{all_params_str}#{encoding_remarks}"
                );
                println!("{}", vless_link);
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
                    "trojan://{password}@{server}:{port}/?{all_params_str}#{encoding_remarks}"
                );
                println!("{}", trojan_link);
            }
            _ => println!("不支持{proxytype}类型的代理"),
        }
    } else {
        println!("{config_path}文件的数据格式不匹配！");
    }
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
