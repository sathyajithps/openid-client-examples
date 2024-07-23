use std::{
    io::{Read, Write},
    net::TcpListener,
};

pub fn local_server_cb_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:4444").unwrap();

    let mut cb_url = "".to_string();

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let mut buf = [0u8; 4096];
                stream.read(&mut buf).unwrap();
                let req_str = String::from_utf8_lossy(&buf);
                let (_, other) = req_str.split_at(4);
                let idx: Vec<_> = other.match_indices(" HTTP/1.1").collect();
                let (url, _) = other.split_at(idx.first().unwrap().0);

                cb_url = format!("http://localhost:4444{url}");

                stream.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<html><body>Open the CLI</body></html>\r\n").unwrap();

                break;
            }
            Err(_) => {
                panic!("Server error");
            }
        }
    }

    cb_url
}

pub fn local_server_post_logout() {
    let listener = TcpListener::bind("127.0.0.1:5555").unwrap();

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let mut buf = [0u8; 4096];
                stream.read(&mut buf).unwrap();
                let req_str = String::from_utf8_lossy(&buf);
                let (_, other) = req_str.split_at(4);
                let idx: Vec<_> = other.match_indices(" HTTP/1.1").collect();
                let (url, _) = other.split_at(idx.first().unwrap().0);

                println!("URL: {url}");

                stream.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<html><body>Open the CLI</body></html>\r\n").unwrap();

                break;
            }
            Err(_) => {
                panic!("Server error");
            }
        }
    }
}
