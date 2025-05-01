use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use httparse;
use std::net::{TcpListener, TcpStream};
use std::{str, time};
use std::sync::{Arc, RwLock, RwLockReadGuard};
use std::thread;
use chrono::{Local, Utc};
use clap::{Parser, Subcommand};
use daemonize::Daemonize;
use futures::executor::block_on;
use rustls_acme::{is_tls_alpn_challenge, AcmeConfig, UseChallenge};
use signal_hook::consts::{SIGHUP, SIGTERM};
use signal_hook::iterator::Signals;
use threadpool::ThreadPool;
use futures::prelude::*;
use rustls_acme::caches::DirCache;
use rustls_acme::futures_rustls::LazyConfigAcceptor;
use rustls_acme::futures_rustls::server::TlsStream;
use tracing_subscriber::FmtSubscriber;

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

  /// addr to listen http requests
  #[arg(long, value_delimiter = ' ', default_value = "0.0.0.0:80")]
  http_host: String,

  /// addr to listen https requests
  #[arg(long, value_delimiter = ' ', default_value = "0.0.0.0:443")]
  https_host: String,

  /// max handler threads
  #[arg(short, long, default_value_t = 1024)]
  max: usize,
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

struct BlockingTlsStream {
  inner: TlsStream<smol::net::TcpStream>,
}

impl Read for BlockingTlsStream {
  fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
    block_on(self.inner.read(buf))
  }
}

impl Write for BlockingTlsStream {
  fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
    block_on(self.inner.write(buf))
  }

  fn flush(&mut self) -> std::io::Result<()> {
    block_on(self.inner.flush())
  }
}

impl Drop for BlockingTlsStream {
  fn drop(&mut self) {
    block_on(self.inner.close()).unwrap()
  }
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

fn fetch_config(keys: &Arc<RwLock<Vec<String>>>, config: &Arc<RwLock<HashMap<String, String>>>, path: &str) {
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
            if arg_tmp.starts_with("res-") && config_lock.get(&format!("{key}_rproxy")).unwrap().eq("1") { panic!("res symbol is only available for static response.") }
            if arg_tmp.starts_with("res-") && config_lock.get(&format!("{key}_static")).unwrap().eq("1") { config_lock.insert(format!("{key}_res"), String::from(arg_tmp.split("-").nth(1).unwrap())); }
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

fn get_matched_host_key<'a>(keys: &Arc<RwLock<Vec<String>>>, host: &str, path: &str) -> Result<String, &'a str> {
  let key_lock =  keys.read().unwrap();
  let mut key_iter = key_lock.iter();

  let search = key_iter.find(|&x| x == host);

  match search {
    Some(d) => {
      if d.contains("/") && !path.starts_with(&d[d.find("/").unwrap()..]) { Err("Not found") }
      else { Ok(String::from(d)) }
    },
    None => Err("Not found"),
  }
}

fn get_config(config_lock: &RwLockReadGuard<HashMap<String, String>>, target: &str, key: &str) -> String {
  String::from(config_lock.get(&format!("{target}_{key}")).unwrap())
}

// functionality
fn handle_request<S: Read + Write>(mut stream: S, keys: &Arc<RwLock<Vec<String>>>, config: &Arc<RwLock<HashMap<String, String>>>, peer_addr: &str) {

  let mut header_buf = Vec::new();
  let mut packet_buf = Vec::new();

  let success = {
    let mut reader = BufReader::new(&mut stream);
    loop {
      let mut buffer = Vec::new();
      match reader.read_until(b'\n', &mut buffer) {
        Ok(0) => break false,
        Ok(_) => (),
        Err(_) => break false,
      }
      packet_buf.extend_from_slice(&buffer);
      header_buf.extend_from_slice(&buffer);
      if packet_buf.ends_with(b"\r\n\r\n") { break true; }
    }
  };

  if !success {
    stream.write(build_packet("502", "Bad Gateway", "Upstream closed connection unexpectedly").as_bytes()).unwrap();
    stream.flush().unwrap();
    return;
  }

  let mut headers = [httparse::EMPTY_HEADER; 32];
  let mut req = httparse::Request::new(&mut headers);

  match req.parse(&header_buf) {
      Ok(httparse::Status::Complete(_)) => {}
      _ => {
          stream.write(build_packet("400", "Bad Request", "Malformed Request").as_bytes()).unwrap();
          stream.flush().unwrap();
          return;
      }
  }

  let path = req.path.unwrap_or("");

  let host = req.headers.iter()
      .find(|h| h.name.eq_ignore_ascii_case("Host"))
      .map(|h| str::from_utf8(h.value).unwrap_or(""))
      .unwrap_or("");

  let content_length = req.headers.iter()
      .find(|h| h.name.eq_ignore_ascii_case("Content-Length"))
      .map(|h| str::from_utf8(h.value).unwrap_or("0"))
      .unwrap_or("0")
      .parse::<usize>()
      .unwrap_or(0);

  print!("[LOG] {}{}   {} {}{}\n", Local::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(), Local::now().offset().to_string(), peer_addr, host, path);

  let target = get_matched_host_key(&keys, &host, &path);
  match &target {
    Ok(d) => {
      let config_lock = config.read().unwrap();
      if get_config(&config_lock, d, "static").eq("1") {
        stream.write(build_packet(&get_config(&config_lock, d, "res"), "OK", &get_config(&config_lock, d, "target")).as_bytes()).unwrap();
      }else if get_config(&config_lock, d, "rproxy").eq("1") {
        if content_length != 0 {
          let mut reader = BufReader::new(&mut stream);
          let mut buffer = vec![0u8; content_length];
          reader.read_exact(&mut buffer).unwrap();
          packet_buf.extend_from_slice(&buffer);
        }

        let mut tcp_client = TcpStream::connect(get_config(&config_lock, d, "target")).unwrap();
        tcp_client.write(&packet_buf).unwrap();
        tcp_client.flush().unwrap();

        // res
        let mut client_res = Vec::new();
        let mut client_header = Vec::new();
        let mut client_reader = BufReader::new(&mut tcp_client);
        loop {
          let mut buffer = Vec::new();
          client_reader.read_until(b'\n', &mut buffer).unwrap();
          if buffer.is_empty() { panic!("Error: Stream closed before headers complete"); }

          client_res.extend_from_slice(&buffer);
          client_header.extend_from_slice(&buffer);

          if client_res.ends_with(b"\r\n\r\n") { break };
        }

        let mut client_headers = [httparse::EMPTY_HEADER; 32];
        let mut client_req = httparse::Response::new(&mut client_headers);
        match client_req.parse(&client_header) {
          Ok(httparse::Status::Complete(_)) => {}
          _ => {
            stream.write(build_packet("400", "Bad Request", "Malformed Request").as_bytes()).unwrap();
            stream.flush().unwrap();
            return;
          },
        }
        let content_length = client_req.headers.iter()
            .find(|h| h.name.eq_ignore_ascii_case("Content-Length"))
            .map(|h| str::from_utf8(h.value).unwrap_or("0"))
            .unwrap_or("0")
            .parse::<usize>()
            .unwrap_or(0);
        if content_length != 0 {
          let mut total = 0;
          let mut buffer = vec![0u8; content_length];
          while total < content_length {
            let read_bytes = client_reader.read(&mut buffer[total..]).unwrap();
            if read_bytes == 0 {
              panic!("Unexpected EOF: read {total} of {content_length} bytes");
            }
            total += read_bytes;
          }
          client_res.extend_from_slice(&buffer);
        }

        stream.write(&client_res).unwrap();
        stream.flush().unwrap();
      }
    },
    Err(_) => {
      stream.write(build_packet("404", "Not Found", "Not Found").as_bytes()).unwrap();
    }
  }

  stream.flush().unwrap();
}

fn listen(args: &Args, keys: &Arc<RwLock<Vec<String>>>, config: &Arc<RwLock<HashMap<String, String>>>) {
  let hosts: Vec<String> = {
    let tmp_lock = keys.read().unwrap();
    tmp_lock
        .iter()
        .filter_map(|x| x.split('/').next().map(|s| s.to_string()))
        .filter(|x| !x.is_empty())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect()
  };


  let pool = ThreadPool::new(args.max);
  {
    let keys1 = Arc::clone(&keys);
    let keys2 = Arc::clone(&keys);
    let config1 = Arc::clone(&config);
    let config2 = Arc::clone(&config);
    let pool1 = ThreadPool::clone(&pool);
    let pool2 = ThreadPool::clone(&pool);

    let host = String::clone(&args.http_host);
    let http_thread = thread::spawn(move || {
      let http_listener = TcpListener::bind(&host).unwrap();

      for stream in http_listener.incoming() {
        let stream = stream.unwrap();
        let keys = Arc::clone(&keys1);
        let config = Arc::clone(&config1);

        pool1.execute(move || {
          let addr = stream.peer_addr().unwrap();
          handle_request(&stream, &keys, &config, &addr.to_string());
        });
      }
    });

    let host = String::clone(&args.https_host);
    let https_thread = thread::spawn(move || {
      smol::block_on(async {
          let https_listener = smol::net::TcpListener::bind(&host).await.unwrap();

        let mut state = AcmeConfig::new(hosts.clone())
            .directory_lets_encrypt(true)
            .challenge_type(UseChallenge::Http01)
            .cache(DirCache::new("/etc/split/certs"))
            .state();

        let challenge_rustls_config = state.challenge_rustls_config();
        let default_rustls_config = state.default_rustls_config();

        smol::spawn(async move {
          loop {
            match state.next().await.unwrap() {
              Ok(ok) => println!("event: {:?}", ok),
              Err(err) => {
                println!("error: {:?}", err)
              },
            }
          }
        }).detach();

        while let Some(tcp) = https_listener.incoming().next().await {
            let challenge_rustls_config = challenge_rustls_config.clone();
            let default_rustls_config = default_rustls_config.clone();

            let stream = tcp.unwrap();
            let addr = stream.peer_addr().unwrap();

            let keys = Arc::clone(&keys2);
            let config = Arc::clone(&config2);

            pool2.execute(move || {
              smol::block_on(async move {
                let start_handshake = LazyConfigAcceptor::new(Default::default(), stream).await.unwrap();

                if is_tls_alpn_challenge(&start_handshake.client_hello()) {
                  println!("received TLS-ALPN-01 validation request");
                  let mut tls = start_handshake.into_stream(challenge_rustls_config).await.unwrap();
                  tls.close().await.unwrap();
                } else {
                  let tls = match start_handshake.into_stream(default_rustls_config).await {
                    Ok(tls) => tls,
                    Err(e) => {
                      println!("TLS handshake failed: {:?}", e);
                      return;
                    }
                  };
                  let mut blocking_stream  = BlockingTlsStream { inner: tls };

                  handle_request(&mut blocking_stream, &keys, &config, &addr.to_string());
                  drop(blocking_stream);
                }
              })
            });
          }
        });
    });

    println!("Listening on {} for http traffic", &args.http_host);
    println!("Listening on {} for https traffic", &args.https_host);

    http_thread.join().unwrap();
    https_thread.join().unwrap();
  }
}

fn demonize(args: &Args, keys: &Arc<RwLock<Vec<String>>>, config: &Arc<RwLock<HashMap<String, String>>>) {
  let subscriber = FmtSubscriber::builder()
      .with_max_level(tracing::Level::INFO)
      .finish();

  tracing::subscriber::set_global_default(subscriber)
      .expect("setting default subscriber failed");

  fetch_config(&keys, &config, &args.conf);

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
            fetch_config(&keys, &config, &conf_file);
            println!("Successfully reloaded configuration.");
          }
          _ => (),
        }
      }
    });
  }

  listen(&args, &keys, &config);
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
      thread::sleep(time::Duration::from_millis(10));
      println!("restarted daemon");
      demonize(&args, &keys, &config);
    }
  }
}
