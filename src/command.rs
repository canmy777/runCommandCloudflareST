use std::io::{ self, Write };
use tokio::{ io::{ AsyncBufReadExt, BufReader }, process::Command };

/// 运行子进程并处理输出与信号
pub async fn run_cloudflare_st(
    program: &str,
    args: Vec<&str>
) -> Result<(), Box<dyn std::error::Error>> {
    // 启动子进程
    let mut child = Command::new(program)
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("未能生成子进程");

    // 获取子进程的标准输出
    let child_stdout = child.stdout.take().expect("捕获标准输出失败");

    // 创建读取子进程输出的任务
    let read_child_task = tokio::spawn(read_child_output(child_stdout));

    // 等待 Ctrl+C 信号
    let signal_task = tokio::signal::ctrl_c();

    tokio::select! {
        _ = signal_task => {
            // 收到 Ctrl+C 信号，杀死子进程
            println!("\n\n收到Ctrl+C信号，杀死子进程...");
            if let Err(e) = child.kill().await {
                eprintln!("\n\n杀死子进程失败: {}", e);
            }
            std::process::exit(0);
        }
        _ = read_child_task => {
            // 子进程输出读取完成
            // println!("子进程输出任务完成。");
        }
    }

    // 等待子进程退出
    let _status = child.wait().await.unwrap();
    // println!("子进程的状态：{}", status);

    Ok(())
}

/// 获取子进程输出并打印
async fn read_child_output(child_stdout: tokio::process::ChildStdout) {
    let reader = BufReader::new(child_stdout);
    let mut lines = reader.lines();
    let mut count = 0;
    while let Ok(Some(line)) = lines.next_line().await {
        if line.contains("Ctrl+C") || line.contains("回车键") {
            continue; // 忽略原来CloudflareST.exe程序中的字符串
        } else if count >= 2 {
            if line.contains("完整测速结果已写入") && line.contains("可使用记事本/表格软件查看") {
                print!("{}按 Enter 键继续！", line);
                io::stdout().flush().unwrap();
            } else {
                println!("{}", line);
            }
        }
        count += 1;
    }
}
