fn eprint<T: std::fmt::Display>(msg: T) {
    let _ = writeln!(&mut io::stderr(), "{}", msg);
}

/// Read a message from stdin and decode it.
fn get_message() -> serde_json::Value {
    let mut raw_length = [0; 4];
    io::stdin()
        .read_exact(&mut raw_length)
        .expect("Failed to read message length");
    let message_length = u32::from_le_bytes(raw_length);
    let mut message = vec![0; message_length as usize];
    io::stdin()
        .read_exact(&mut message)
        .expect("Failed to read message content");
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open("/Users/JANG/rpass_test.log")
        .expect("Failed to open file");
    writeln!(
        &mut f,
        "{}",
        serde_json::to_string(&message_length).unwrap()
    )
    .unwrap();
    serde_json::from_slice(message.as_slice()).expect("Failed to parse JSON")
}

/// Encode a message for transmission, given its content.
fn encode_message<T: Serialize>(message_content: &T) -> Vec<u8> {
    let encoded_content = serde_json::to_vec(message_content).expect("Failed to encode JSON");
    let encoded_length = (encoded_content.len() as u32).to_le_bytes();
    [&encoded_length, encoded_content.as_slice()].concat()
}

/// Send an encoded message to stdout
fn send_message(encoded_message: &[u8]) {
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open("/Users/JANG/rpass_test.log")
        .expect("Failed to open file");
    writeln!(
        &mut f,
        "{}",
        serde_json::to_string(&format!("encoded_message: {:?}", encoded_message)).unwrap()
    )
    .unwrap();
    io::stdout()
        .write_all(encoded_message)
        .expect("Failed to write to stdout");
    io::stdout().flush().expect("Failed to flush stdout");
}

fn main() {
    loop {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open("/Users/JANG/rpass_test.log")
            .expect("Failed to open file");
        let received_message = get_message();
        writeln!(
            &mut f,
            "{}",
            serde_json::to_string(&received_message).unwrap()
        )
        .unwrap();

        if received_message == serde_json::json!("ping") {
            let response = serde_json::json!("pong");
            let encoded_message = encode_message(&response);
            send_message(&encoded_message);
        } else {
            let response = "I am from native host!!";

            let encoded_message = encode_message(&response);
            send_message(&encoded_message);
        }
        let mut store = PasswordStore::new(
            "test",
            &Some(PathBuf::from("/Users/JANG/.password-store")),
            &Some("F40F BF4B 0253 39DE A21D  3D2D 3E1D DD12 57F3 A8F1".to_string()),
            &Some(PathBuf::from("/Users/JANG/")),
            &None,
            &CryptoImpl::GpgMe,
            // fingerprint: F40F BF4B 0253 39DE A21D  3D2D 3E1D DD12 57F3 A8F1
            &None,
            // &Some([
            //     0xf4, 0x0f, 0xbf, 0x4b, 0x02, 0x53, 0x39, 0xde, 0xa2, 0x1d, 0x3d, 0x2d, 0x3e, 0x1d,
            //     0xdd, 0x12, 0x57, 0xf3, 0xa8, 0xf1,
            // ]),
        );
    }
}
