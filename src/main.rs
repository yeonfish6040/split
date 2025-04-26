use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::str;
use std::sync::{Arc, RwLock};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};
use chrono::{Local, Utc};
use clap::{Parser, Subcommand};
use daemonize::Daemonize;
use signal_hook::consts::{SIGHUP, SIGTERM};
use signal_hook::iterator::Signals;

#[derive(Parser, Debug)]
#[clap(disable_help_flag = true)]
#[command(version, about, long_about = None)]
struct Args {
  /// prints this page
  #[clap(long, action = clap::ArgAction::HelpLong)]
  help: Option<bool>,

  /// decide the action
  #[command(subcommand)]
  command: Commands,
  
  /// configuration file location
  #[arg(short, long, default_value_t = String::from("/etc/split/split.conf"))]
  conf: String,

  /// addr to listen
  #[arg(short, long, value_delimiter = ' ', default_values = ["0.0.0.0:80", "0.0.0.0:443"])]
  addr: Option<Vec<String>>,

  /// max handler threads
  #[arg(short, long, default_value_t = 1024)]
  max: u64,
}

#[derive(Subcommand, Debug)]
enum Commands {
  /// start daemon
  Start,
  /// stop daemon
  Stop,
  /// reload daemon
  Restart,
  /// reload daemon
  Reload,
}

// utils
fn get_pid() -> i32 {
  let pid_file = std::fs::read_to_string("/var/run/split.pid");
  match pid_file {
    Ok(d) => d.trim().parse::<i32>().unwrap(),
    Err(e) if e.kind() == ErrorKind::PermissionDenied => {
      println!("Error: Permission Denied. Are you executing command as root?");
      std::process::exit(1);
    }
    Err(e) if e.kind() == ErrorKind::NotFound => {
      println!("Cannot find any running daemon. Is split currently running?");
      std::process::exit(1);
    }
    Err(e) => {
      println!("IOError: {:?}", e.kind());
      std::process::exit(1);
    }
  }
}

fn get_config(keys: &Arc<RwLock<Vec<String>>>, config: &Arc<RwLock<HashMap<String, String>>>, path: &str) {
  let mut config_lock = config.write().unwrap();
  let mut keys_lock = keys.write().unwrap();

  config_lock.clear();

  let config_file = match std::fs::read_to_string(path) {
    Ok(d) => d,
    Err(e) if e.kind() == ErrorKind::PermissionDenied => {
      println!("Cannot read configuration file: Permission denied");
      std::process::exit(1);
    }
    Err(e) => {
      println!("Error: {:?}", e);
      std::process::exit(1);
    }
  };
  let configs = config_file.split("\n").collect::<Vec<&str>>();

  for (i, el) in configs.iter().enumerate() {
    if el.is_empty() {
      continue;
    }
    if el.starts_with("#") {
      continue;
    }
    if !(el.contains("=>") || el.contains("<=")) {
      panic!("Error: Cannot parse symbol on line {i}.\n=> or <= not found on that line: {el}")
    }
    let parse = el.split("").collect::<Vec<&str>>();
    let mut is_end_of_arg;
    let mut is_in_pair = false;
    let mut is_rslash_before = false;
    let mut index = 0;
    let mut key = String::from("");
    let mut arg_tmp = String::from("");
    for (j, el1) in parse.iter().enumerate() {
      arg_tmp.push_str(el1);
      if el1 == &"#" && !is_rslash_before { break } // comment
      if el1 == &" " && !is_in_pair { index += 1; is_end_of_arg = true; arg_tmp.pop(); } else { is_end_of_arg = false }
      if el.len() == j+1 { index += 1; is_end_of_arg = true }
      if el1 == &"\"" && !is_rslash_before && !is_in_pair { is_in_pair = true; arg_tmp.pop(); }
      else if el1 == &"\"" && !is_rslash_before && is_in_pair { is_in_pair = false; arg_tmp.pop(); }

      if el1 == &"\\" { is_rslash_before = true } else { is_rslash_before = false }
      if is_end_of_arg {
        config_lock.insert(format!("{key}_https"), String::from("1"));
        config_lock.insert(format!("{key}_verification"), String::from("1"));
        config_lock.insert(format!("{key}_res"), String::from("200"));
        match index {
          1 => {
            key = arg_tmp.clone();
            keys_lock.push(key.clone());
          }
          2 => {
            match &arg_tmp[..] {
              "<=" => {
                config_lock.insert(format!("{key}_rproxy"), String::from("0"));
                config_lock.insert(format!("{key}_static"), String::from("1"));
              }
              "=>" => {
                config_lock.insert(format!("{key}_rproxy"), String::from("1"));
                config_lock.insert(format!("{key}_static"), String::from("0"));
              }
              _ => {
                panic!("Error: Cannot parse symbol on line {i}.\nUnexpected symbol: {arg_tmp}. \"<=\" or \"=>\" expected");
              }
            }
          }
          3 => {
            config_lock.insert(format!("{key}_target"), arg_tmp.clone());
          }
          _ => {
            if arg_tmp.as_str() == "disable-https" { config_lock.insert(format!("{key}_https"), String::from("0")); }
            if arg_tmp.as_str() == "disable-verification" { config_lock.insert(format!("{key}_verification"), String::from("0")); }
            if arg_tmp.starts_with("res-") && config_lock.get("{key}_rproxy").unwrap().eq("1") { panic!("res symbol is only available for static response.") }
            if arg_tmp.starts_with("res-") && config_lock.get("{key}_static").unwrap().eq("1") { config_lock.insert(format!("{key}_res"), String::from(arg_tmp.split("-").nth(1).unwrap())); }
            // println!("{}", arg_tmp);
          }
        }
      }
      if is_end_of_arg { arg_tmp.clear() }
    }
    // println!("{}, {}", i + 1, el);
  }
  // println!("{:?}", config_lock.iter().collect::<Vec<_>>());
}

fn build_packet(res_code: &str, res_msg: &str, body: &str) -> String {
  let mut packet = String::from("");
  packet.push_str(&format!("HTTP/1.1 {res_code} {res_msg}\n"));
  packet.push_str("X-Powered-By: Split\n");
  packet.push_str("Access-Control-Allow-Origin: *\n");
  packet.push_str("Content-Type: text/html; charset=utf-8\n");
  packet.push_str(&format!("Content-Length: {}\n", body.len()));
  packet.push_str(&format!("Date: {}\n", Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string()));
  packet.push_str("Connection: keep-alive\n");
  packet.push_str("Keep-Alive: timeout=5\n");
  packet.push_str("\n");
  packet.push_str(body);

  packet
}

// functionality
fn handle_request(thread_count: Arc<RwLock<u64>>, mut stream: TcpStream, keys: &Arc<RwLock<Vec<String>>>, config: &Arc<RwLock<HashMap<String, String>>>) {
  let mut buffer = [0u8; 16838];

  let size: usize = stream.read(&mut buffer).unwrap();

  let s = match str::from_utf8(&buffer[..size]) {
    Ok(v) => v,
    Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
  };

  let mut lines =  s.lines();
  let path = lines.next().unwrap().split(" ").nth(1).unwrap();
  let host = lines.find(|&x| x.starts_with("Host:")).unwrap().split(" ").nth(1).unwrap();
  print!("[LOG] {}{}   {} {}{}\n", Local::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(), Local::now().offset().to_string(), stream.peer_addr().unwrap(), host, path);

  let target = {
    let key_lock =  keys.read().unwrap();
    let mut key_iter = key_lock.iter();

    let search = key_iter.find(|&x| {
      let host_tmp = x.split('/').next().unwrap_or(x);
      if host_tmp.starts_with('*') {
        // suffix
        let suffix = &host_tmp[1..];
        host.ends_with(suffix)
      } else if host_tmp.ends_with('*') {
        // prefix
        let prefix = &host_tmp[..host_tmp.len()-1];
        host.starts_with(prefix)
      } else {
        host == host_tmp
      }
    });

    match search {
      Some(d) => Ok(String::from(d)),
      None => Err("Not found"),
    }
  };

  match target {
    Ok(d) => {},
    Err(e) => {
      stream.write(build_packet("404", "Not Found", "Not Found").as_bytes()).expect("ahhhhhhhh!");
    }
  }

  // stream.write(format!("{s}").as_bytes()).expect("ahhhhhhhh!");
  stream.flush().unwrap();
}

fn start(args: &Args, keys: &Arc<RwLock<Vec<String>>>, config: &Arc<RwLock<HashMap<String, String>>>) {
  let mut listeners = Vec::<TcpListener>::new();
  for host in args.addr.clone().unwrap() {
    listeners.push(TcpListener::bind(&host).unwrap());
    println!("{}", format!("Currently listening on {host}"));
  }

  let mut threads = Vec::<JoinHandle<()>>::new();
  for listener in listeners {
    let keys = Arc::clone(&keys);
    let config = Arc::clone(&config);
    let thread_count = Arc::new(RwLock::new(0u64));
    let max_threads = args.max;
    let thread = thread::spawn(move || {
      for stream in listener.incoming() {
        let stream = stream.unwrap();
        let keys = Arc::clone(&keys);
        let config = Arc::clone(&config);
        let thread_count = Arc::clone(&thread_count);

        while thread_count.read().unwrap().ge(&max_threads) { thread::sleep(Duration::from_millis(10)); }
        thread::spawn(move || {
          let thread_count_clone = Arc::clone(&thread_count);
          { let mut cnt = thread_count_clone.write().unwrap(); *cnt += 1; }
          handle_request(thread_count, stream, &keys, &config);
          { let mut cnt = thread_count_clone.write().unwrap(); *cnt -= 1; }
        });
      }
    });
    threads.push(thread);
  }
  for thread in threads {
    thread.join().expect("Cannot join thread.");
  }
}

fn demonize(args: &Args, keys: &Arc<RwLock<Vec<String>>>, config: &Arc<RwLock<HashMap<String, String>>>) {
  get_config(&keys, &config, &args.conf);

  // demonize
  let daemon = Daemonize::new()
      .pid_file("/var/run/split.pid")
      .working_directory("/etc/split")
      .stdout(std::fs::File::create("/var/log/split.out").unwrap())
      .stderr(std::fs::File::create("/var/log/split.err").unwrap());
  match daemon.start() {
    Ok(_) => (),
    Err(e) => {
      println!("{:?}", e);
    }
  }

  // signal listener
  {
    let keys = Arc::clone(&keys);
    let config = Arc::clone(&config);
    let conf_file = args.conf.clone();
    let mut signals = Signals::new(&[SIGTERM, SIGHUP]).unwrap();
    thread::spawn(move || {
      for sig in signals.forever() {
        match sig {
          SIGTERM => {
            std::fs::remove_file("/var/run/split.pid")
                .expect("Error: Cannot delete pid file.");
            println!("Received SIGTERM. Exiting.");
            std::process::exit(0);
          }
          SIGHUP => {
            println!("reloading configuration…");
            get_config(&keys, &config, &conf_file);
            println!("Successfully reloaded configuration.");
          }
          _ => (),
        }
      }
    });
  }

  start(&args, &keys, &config);
}

fn main() {
  let args = Args::parse();
  let keys = Arc::new(RwLock::new(Vec::<String>::new()));
  let config = Arc::new(RwLock::new(HashMap::<String, String>::new()));

  match args.command {
    Commands::Start => {
      println!("started daemon");
      demonize(&args, &keys, &config);
    }

    Commands::Stop => {
      let pid = get_pid();
      nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), nix::sys::signal::SIGTERM)
        .unwrap();
      println!("daemon stopped");
    }

    Commands::Reload => {
      let pid = get_pid();
      nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), nix::sys::signal::SIGHUP)
        .unwrap();
      println!("daemon reloaded");
    }

    Commands::Restart => {
      let pid = get_pid();
      nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), nix::sys::signal::SIGTERM)
          .unwrap();
      println!("restarted daemon");
      demonize(&args, &keys, &config);
    }
  }
}
