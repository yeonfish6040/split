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
use rustls_acme::{is_tls_alpn_challenge, AcmeConfig, ResolvesServerCertAcme, UseChallenge};
use signal_hook::consts::{SIGHUP, SIGTERM};
use signal_hook::iterator::Signals;
use threadpool::ThreadPool;
use futures::prelude::*;
use httparse::{Request, Response};
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

trait HasHeaders<'a> {
  fn headers(&self) -> &[httparse::Header<'a>];
}

impl<'a, 'b> HasHeaders<'a> for Request<'a, 'b> {
  fn headers(&self) -> &[httparse::Header<'a>] {
    self.headers
  }
}

impl<'a, 'b> HasHeaders<'a> for Response<'a, 'b> {
  fn headers(&self) -> &[httparse::Header<'a>] {
    self.headers
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
fn transfer_data<'a, Src, Dest, H>(
  mut client_reader: BufReader<&mut Src>,
  mut target_stream: Dest,
  client_req: &H,
) -> Result<Dest, ()>
where
    Src: Read + Write + Send + 'static,
    Dest: Read + Write + Send + 'static,
    H: HasHeaders<'a> + Send + Sync,
{
  let mut req_type = "";
  if client_req.headers().iter().any(|h| h.name.eq_ignore_ascii_case("Transfer-Encoding") && str::from_utf8(h.value).unwrap_or("").contains("chunked")) {
    req_type = "chunked";
  }

  match req_type {
    "chunked" => {
      loop {
        let mut line = Vec::new();
        client_reader.read_until(b'\n', &mut line).unwrap();
        if line.is_empty() { break; }
        target_stream.write_all(&line).unwrap();

        let chunk_size_line = String::from_utf8_lossy(&line);
        if chunk_size_line.trim() == "0" {
          let mut trailer = Vec::new();
          client_reader.read_until(b'\n', &mut trailer).unwrap();
          target_stream.write_all(&trailer).unwrap();
          break;
        }

        let chunk_size = usize::from_str_radix(chunk_size_line.trim(), 16).unwrap();
        let mut chunk = vec![0u8; chunk_size + 2];
        client_reader.read_exact(&mut chunk).unwrap();
        target_stream.write_all(&chunk).unwrap();
        target_stream.flush().unwrap();
      }
    }
    _ => {
      let content_length = client_req.headers().iter()
          .find(|h| h.name.eq_ignore_ascii_case("Content-Length"))
          .map(|h| str::from_utf8(h.value).unwrap_or("0"))
          .unwrap_or("0")
          .parse::<usize>()
          .unwrap_or(0);

      let mut buf = vec![0u8; content_length];
      client_reader.read_exact(&mut buf).unwrap();
      target_stream.write_all(&buf).unwrap();
      target_stream.flush().unwrap();
    }
  }

  Ok(target_stream)
}

fn handle_request<S: Read + Write + Send + 'static>(mut client_stream: S, keys: &Arc<RwLock<Vec<String>>>, config: &Arc<RwLock<HashMap<String, String>>>, peer_addr: &str, resolver: Arc<ResolvesServerCertAcme>) {
  let mut client_req_header_buf = Vec::new();
  let mut client_req_reader = BufReader::new(&mut client_stream);

  loop {
    let mut buffer = Vec::new();
    client_req_reader.read_until(b'\n', &mut buffer).unwrap();
    if buffer.is_empty() { panic!("Error: Stream closed before headers complete"); }

    client_req_header_buf.extend_from_slice(&buffer);

    if client_req_header_buf.ends_with(b"\r\n\r\n") { break };
  }

  let mut client_req_header = [httparse::EMPTY_HEADER; 32];
  let mut client_req = Request::new(&mut client_req_header);

  match client_req.parse(&client_req_header_buf) {
    Ok(httparse::Status::Complete(_)) => {}
    _ => {
      client_stream.write(build_packet("400", "Bad Request", "Malformed Request").as_bytes()).unwrap();
      client_stream.flush().unwrap();
      return;
    }
  }

  let is_websocket = client_req.headers.iter()
      .any(|h| h.name.eq_ignore_ascii_case("Upgrade")
           && str::from_utf8(h.value).unwrap_or("")
                  .eq_ignore_ascii_case("websocket"));

  let path = client_req.path.unwrap_or("");
  if path.starts_with("/.well-known/acme-challenge/") {
    let token = path.rsplit('/').next().unwrap_or_default();
    if let Some(key_auth) = resolver.get_http_01_key_auth(token) {
      let body = key_auth;
      let resp = build_packet("200", "OK", &body);
      client_stream.write_all(resp.as_bytes()).unwrap();
    } else {
      client_stream.write_all(build_packet("404", "Not Found", "Not Found").as_bytes()).unwrap();
    }
    return;
  }

  let host = client_req.headers.iter()
      .find(|h| h.name.eq_ignore_ascii_case("Host"))
      .map(|h| str::from_utf8(h.value).unwrap_or(""))
      .unwrap_or("");

  print!("[LOG] {}{}   {} {}{}\n", Local::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(), Local::now().offset().to_string(), peer_addr, host, path);

  let target = get_matched_host_key(&keys, &host, &path);
  match &target {
    Ok(host_key) => {
      let config_lock = config.read().unwrap();
      if get_config(&config_lock, host_key, "static").eq("1") {
        client_stream.write(build_packet(&get_config(&config_lock, host_key, "res"), "OK", &get_config(&config_lock, host_key, "target")).as_bytes()).unwrap();
      } else if get_config(&config_lock, host_key, "rproxy").eq("1") {

        let mut target_stream = TcpStream::connect(get_config(&config_lock, host_key, "target")).unwrap();
        target_stream.write_all(&client_req_header_buf).unwrap();
        target_stream.flush().unwrap();

        if is_websocket {
          let mut target_res_header_buf = Vec::new();
          let mut target_res_reader = BufReader::new(target_stream);
          loop {
            let mut buffer = Vec::new();
            target_res_reader.read_until(b'\n', &mut buffer).unwrap();
            if buffer.is_empty() { break; }
            target_res_header_buf.extend_from_slice(&buffer);
            if target_res_header_buf.ends_with(b"\r\n\r\n") { break }
          }

          drop(client_req_reader);

          client_stream.write_all(&target_res_header_buf).unwrap();
          client_stream.flush().unwrap();

          use std::sync::{Arc, Mutex};
          let client_arc = Arc::new(Mutex::new(client_stream));
          let server_arc = Arc::new(Mutex::new(target_res_reader.into_inner()));

          {
            let c = Arc::clone(&client_arc);
            let s = Arc::clone(&server_arc);
            thread::spawn(move || {
              std::io::copy(&mut *c.lock().unwrap(), &mut *s.lock().unwrap()).ok();
            });
          }
          {
            let c = Arc::clone(&client_arc);
            let s = Arc::clone(&server_arc);
            thread::spawn(move || {
              std::io::copy(&mut *s.lock().unwrap(), &mut *c.lock().unwrap()).ok();
            });
          }

          return;
        }

        target_stream = transfer_data::<S, TcpStream, Request>(
          client_req_reader,
          target_stream,
          &client_req,
        ).unwrap();

        // 백엔드 응답 헤더 수신
        let mut target_res_header_buf = Vec::new();
        let mut target_res_reader = BufReader::new(&mut target_stream);
        loop {
          let mut buffer = Vec::new();
          target_res_reader.read_until(b'\n', &mut buffer).unwrap();
          if buffer.is_empty() { panic!("Error: Stream closed before headers complete"); }

          target_res_header_buf.extend_from_slice(&buffer);

          if target_res_header_buf.ends_with(b"\r\n\r\n") { break };
        }

        let mut target_res_header = [httparse::EMPTY_HEADER; 32];
        let mut target_res = Response::new(&mut target_res_header);
        match target_res.parse(&target_res_header_buf) {
          Ok(httparse::Status::Complete(_)) => {}
          _ => {
            client_stream.write_all(build_packet("400", "Bad Request", "Malformed Request").as_bytes()).unwrap();
            client_stream.flush().unwrap();
            return;
          },
        }

        client_stream.write_all(&target_res_header_buf).unwrap();
        transfer_data::<TcpStream, S, Response>(
          target_res_reader,
          client_stream,
          &target_res,
        ).unwrap();
      }
    }
    Err(_) => {
      client_stream.write_all(build_packet("404", "Not Found", "Not Found").as_bytes()).unwrap();
    } 
  }
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
    let mut state = AcmeConfig::new(hosts.clone())
        .directory_lets_encrypt(true)
        .challenge_type(UseChallenge::Http01)
        .cache(DirCache::new("/etc/split/certs"))
        .state();

    let challenge_rustls_config = state.challenge_rustls_config();
    let default_rustls_config = state.default_rustls_config();

    let keys1 = Arc::clone(&keys);
    let keys2 = Arc::clone(&keys);
    let config1 = Arc::clone(&config);
    let config2 = Arc::clone(&config);
    let pool1 = ThreadPool::clone(&pool);
    let pool2 = ThreadPool::clone(&pool);

    let host = String::clone(&args.http_host);
    let resolver = state.resolver();
    let http_thread = thread::spawn(move || {
      let http_listener = TcpListener::bind(&host).unwrap();

      for stream in http_listener.incoming() {
        let stream = stream.unwrap();
        let keys = Arc::clone(&keys1);
        let config = Arc::clone(&config1);

        let resolver = resolver.clone();
        pool1.execute(move || {
          let addr = stream.peer_addr().unwrap();
          handle_request(stream, &keys, &config, &addr.to_string(), resolver);
        });
      }
    });

    let host = String::clone(&args.https_host);
    let resolver = state.resolver();
    let https_thread = thread::spawn(move || {
      smol::block_on(async {
        let https_listener = smol::net::TcpListener::bind(&host).await.unwrap();

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

          let resolver = resolver.clone();
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
                let blocking_stream  = BlockingTlsStream { inner: tls };

                handle_request(blocking_stream, &keys, &config, &addr.to_string(), resolver);
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
