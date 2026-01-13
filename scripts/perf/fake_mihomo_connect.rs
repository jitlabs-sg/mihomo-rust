use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::thread;

fn parse_args() -> Option<PathBuf> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-f" | "--config" => {
                if i + 1 < args.len() {
                    return Some(PathBuf::from(args[i + 1].clone()));
                }
                return None;
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn parse_mixed_port(config_path: Option<PathBuf>) -> u16 {
    let Some(path) = config_path else {
        return 17890;
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        return 17890;
    };

    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("mixed-port:") {
            if let Ok(port) = rest.trim().parse::<u16>() {
                return port;
            }
        }
    }
    17890
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
}

fn handle_client(mut client: TcpStream) {
    let mut buf = vec![0u8; 8192];
    let mut n = 0usize;

    loop {
        match client.read(&mut buf[n..]) {
            Ok(0) => return,
            Ok(r) => {
                n += r;
                if let Some(end) = find_header_end(&buf[..n]) {
                    let head = String::from_utf8_lossy(&buf[..end]);
                    let mut lines = head.lines();
                    let Some(req_line) = lines.next() else {
                        return;
                    };
                    let mut parts = req_line.split_whitespace();
                    let method = parts.next().unwrap_or("");
                    let target = parts.next().unwrap_or("");

                    if method.eq_ignore_ascii_case("CONNECT") {
                        let mut host = target;
                        let mut port = 80u16;
                        if let Some((h, p)) = target.rsplit_once(':') {
                            host = h;
                            port = p.parse().unwrap_or(80);
                        }

                        let upstream_addr = format!("{host}:{port}");
                        let Ok(upstream) = TcpStream::connect(upstream_addr) else {
                            let _ = client.write_all(
                                b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n",
                            );
                            return;
                        };

                        let _ = client.write_all(
                            b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: fake-mihomo\r\n\r\n",
                        );

                        let mut client_read = match client.try_clone() {
                            Ok(s) => s,
                            Err(_) => return,
                        };
                        let mut upstream_write = match upstream.try_clone() {
                            Ok(s) => s,
                            Err(_) => return,
                        };

                        let t1 = thread::spawn(move || {
                            let _ = std::io::copy(&mut client_read, &mut upstream_write);
                            let _ = upstream_write.shutdown(Shutdown::Write);
                        });

                        let mut upstream_read = upstream;
                        let mut client_write = client;
                        let _ = std::io::copy(&mut upstream_read, &mut client_write);
                        let _ = client_write.shutdown(Shutdown::Write);

                        let _ = t1.join();
                        return;
                    }

                    let _ = client.write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n");
                    return;
                }

                if n >= buf.len() {
                    let _ = client.write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n");
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

fn main() {
    let config_path = parse_args();
    let port = parse_mixed_port(config_path);
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("valid addr");

    eprintln!("fake_mihomo listening on {addr}");

    let listener = TcpListener::bind(addr).expect("bind");
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                thread::spawn(move || handle_client(stream));
            }
            Err(_) => break,
        }
    }
}
