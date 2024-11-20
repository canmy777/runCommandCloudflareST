use std::{ fs, io::{ self, Write }, str::FromStr };

/// 收集符合条件的所有 .txt 文件路径(cidr数据文件)
pub fn get_file_names(dir_path: &str) -> io::Result<Vec<String>> {
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

/// 获取用户输入的内容，这里使用泛型来写，适配不同的数据类型
pub fn get_user_input<T>(label: &str, mut var: T, vec: Vec<T>) -> T
    where
        /*
         * label: 打印一段提示语，介绍这个动作的用途
         * var：用于存放捕捉用户输入的数值，它确定返回的数据类型
         * vec: 只有用户输入的数组出现在该向量中才跳出死循环
         */
        T: FromStr + ToString + PartialEq // T 必须实现 FromStr, ToString 和 PartialEq trait
{
    loop {
        print!("{}", label);
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let input_string = input.trim().to_string();
        var = T::from_str(&input_string).unwrap_or_else(|_| var); // 读取并转换输入
        if vec.contains(&var) {
            break;
        }
    }
    var
}

/// 从使用的cidr文件路径中，提取国家代码，不符合就返回空字符
#[allow(dead_code)]
pub fn get_country_code(vec: &[&str], input: &str) -> String {
    vec.iter()
        .find(|&&item| input.contains(item))
        .map(|&item| item.to_string())
        .unwrap_or_else(|| "".to_string())
}
