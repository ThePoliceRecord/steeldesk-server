use dns_lookup::{lookup_addr, lookup_host};
use hbb_common::{bail, ResultType};
use sodiumoxide::crypto::sign;
use std::{
    env,
    net::{IpAddr, TcpStream},
    process, str,
};

fn print_help() {
    println!(
        "Usage:
    rustdesk-utils [command]\n
Available Commands:
    genkeypair                                   Generate a new keypair
    validatekeypair [public key] [secret key]    Validate an existing keypair
    doctor [rustdesk-server]                     Check for server connection problems"
    );
    process::exit(0x0001);
}

fn error_then_help(msg: &str) {
    println!("ERROR: {msg}\n");
    print_help();
}

fn gen_keypair() {
    let (pk, sk) = sign::gen_keypair();
    let public_key = base64::encode(pk);
    let secret_key = base64::encode(sk);
    println!("Public Key:  {public_key}");
    println!("Secret Key:  {secret_key}");
}

fn validate_keypair(pk: &str, sk: &str) -> ResultType<()> {
    let sk1 = base64::decode(sk);
    if sk1.is_err() {
        bail!("Invalid secret key");
    }
    let sk1 = sk1.unwrap();

    let secret_key = sign::SecretKey::from_slice(sk1.as_slice());
    if secret_key.is_none() {
        bail!("Invalid Secret key");
    }
    let secret_key = secret_key.unwrap();

    let pk1 = base64::decode(pk);
    if pk1.is_err() {
        bail!("Invalid public key");
    }
    let pk1 = pk1.unwrap();

    let public_key = sign::PublicKey::from_slice(pk1.as_slice());
    if public_key.is_none() {
        bail!("Invalid Public key");
    }
    let public_key = public_key.unwrap();

    let random_data_to_test = b"This is meh.";
    let signed_data = sign::sign(random_data_to_test, &secret_key);
    let verified_data = sign::verify(&signed_data, &public_key);
    if verified_data.is_err() {
        bail!("Key pair is INVALID");
    }
    let verified_data = verified_data.unwrap();

    if random_data_to_test != &verified_data[..] {
        bail!("Key pair is INVALID");
    }

    Ok(())
}

fn doctor_tcp(address: std::net::IpAddr, port: &str, desc: &str) {
    let start = std::time::Instant::now();
    let conn = format!("{address}:{port}");
    if let Ok(_stream) = TcpStream::connect(conn.as_str()) {
        let elapsed = std::time::Instant::now().duration_since(start);
        println!(
            "TCP Port {} ({}): OK in {} ms",
            port,
            desc,
            elapsed.as_millis()
        );
    } else {
        println!("TCP Port {port} ({desc}): ERROR");
    }
}

fn doctor_ip(server_ip_address: std::net::IpAddr, server_address: Option<&str>) {
    println!("\nChecking IP address: {server_ip_address}");
    println!("Is IPV4: {}", server_ip_address.is_ipv4());
    println!("Is IPV6: {}", server_ip_address.is_ipv6());

    // reverse dns lookup
    // TODO: (check) doesn't seem to do reverse lookup on OSX...
    let reverse = lookup_addr(&server_ip_address).unwrap();
    if let Some(server_address) = server_address {
        if reverse == server_address {
            println!("Reverse DNS lookup: '{reverse}' MATCHES server address");
        } else {
            println!(
                "Reverse DNS lookup: '{reverse}' DOESN'T MATCH server address '{server_address}'"
            );
        }
    }

    // TODO: ICMP ping?

    // port check TCP (UDP is hard to check)
    doctor_tcp(server_ip_address, "21114", "API");
    doctor_tcp(server_ip_address, "21115", "hbbs extra port for nat test");
    doctor_tcp(server_ip_address, "21116", "hbbs");
    doctor_tcp(server_ip_address, "21117", "hbbr tcp");
    doctor_tcp(server_ip_address, "21118", "hbbs websocket");
    doctor_tcp(server_ip_address, "21119", "hbbr websocket");

    // TODO: key check
}

fn doctor(server_address_unclean: &str) {
    let server_address3 = server_address_unclean.trim();
    let server_address2 = server_address3.to_lowercase();
    let server_address = server_address2.as_str();
    println!("Checking server:  {server_address}\n");
    if let Ok(server_ipaddr) = server_address.parse::<IpAddr>() {
        // user requested an ip address
        doctor_ip(server_ipaddr, None);
    } else {
        // the passed string is not an ip address
        let ips: Vec<std::net::IpAddr> = lookup_host(server_address).unwrap();
        println!("Found {} IP addresses: ", ips.len());

        ips.iter().for_each(|ip| println!(" - {ip}"));

        ips.iter()
            .for_each(|ip| doctor_ip(*ip, Some(server_address)));
    }
}

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() <= 1 {
        print_help();
    }

    let command = args[1].to_lowercase();
    match command.as_str() {
        "genkeypair" => gen_keypair(),
        "validatekeypair" => {
            if args.len() <= 3 {
                error_then_help("You must supply both the public and the secret key");
            }
            let res = validate_keypair(args[2].as_str(), args[3].as_str());
            if let Err(e) = res {
                println!("{e}");
                process::exit(0x0001);
            }
            println!("Key pair is VALID");
        }
        "doctor" => {
            if args.len() <= 2 {
                error_then_help("You must supply the rustdesk-server address");
            }
            doctor(args[2].as_str());
        }
        _ => print_help(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sodiumoxide::crypto::sign;

    // --- gen_keypair / keypair generation ---

    #[test]
    fn test_gen_keypair_produces_valid_ed25519_keys() {
        let (pk, sk) = sign::gen_keypair();
        let pk_b64 = base64::encode(pk);
        let sk_b64 = base64::encode(&sk);

        // Both should be valid base64 that decodes to the right lengths
        let pk_bytes = base64::decode(&pk_b64).unwrap();
        let sk_bytes = base64::decode(&sk_b64).unwrap();
        assert_eq!(pk_bytes.len(), sign::PUBLICKEYBYTES);
        assert_eq!(sk_bytes.len(), sign::SECRETKEYBYTES);
    }

    #[test]
    fn test_gen_keypair_public_key_derivable_from_secret_key() {
        // Ed25519 secret key is seed||pk, so the public key is the second half
        let (pk, sk) = sign::gen_keypair();
        let derived_pk = &sk[sign::SECRETKEYBYTES / 2..];
        assert_eq!(derived_pk, &pk[..]);
    }

    #[test]
    fn test_gen_keypair_can_sign_and_verify() {
        let (pk, sk) = sign::gen_keypair();
        let message = b"test message for signing";
        let signed = sign::sign(message, &sk);
        let verified = sign::verify(&signed, &pk);
        assert!(verified.is_ok());
        assert_eq!(&verified.unwrap()[..], &message[..]);
    }

    // --- validate_keypair ---

    #[test]
    fn test_validate_keypair_valid_pair() {
        let (pk, sk) = sign::gen_keypair();
        let pk_b64 = base64::encode(pk);
        let sk_b64 = base64::encode(&sk);
        let result = validate_keypair(&pk_b64, &sk_b64);
        assert!(result.is_ok(), "valid keypair should validate: {:?}", result.err());
    }

    #[test]
    fn test_validate_keypair_mismatched_keys() {
        let (_pk1, sk1) = sign::gen_keypair();
        let (pk2, _sk2) = sign::gen_keypair();
        let pk_b64 = base64::encode(pk2);
        let sk_b64 = base64::encode(&sk1);
        let result = validate_keypair(&pk_b64, &sk_b64);
        assert!(result.is_err(), "mismatched keypair should fail validation");
    }

    #[test]
    fn test_validate_keypair_invalid_base64_sk() {
        let result = validate_keypair("AAAA", "not valid base64!!!");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Invalid secret key") || err_msg.contains("Invalid"),
            "error should mention invalid secret key, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_validate_keypair_invalid_base64_pk() {
        let (_pk, sk) = sign::gen_keypair();
        let sk_b64 = base64::encode(&sk);
        let result = validate_keypair("not valid base64!!!", &sk_b64);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Invalid public key") || err_msg.contains("Invalid"),
            "error should mention invalid public key, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_validate_keypair_wrong_length_sk() {
        // Valid base64 but wrong byte length for a secret key
        let short_sk = base64::encode(&[0u8; 16]);
        let (pk, _sk) = sign::gen_keypair();
        let pk_b64 = base64::encode(pk);
        let result = validate_keypair(&pk_b64, &short_sk);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_keypair_wrong_length_pk() {
        // Valid base64 but wrong byte length for a public key
        let short_pk = base64::encode(&[0u8; 16]);
        let (_pk, sk) = sign::gen_keypair();
        let sk_b64 = base64::encode(&sk);
        let result = validate_keypair(&short_pk, &sk_b64);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_keypair_empty_strings() {
        let result = validate_keypair("", "");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_keypair_multiple_generated_pairs() {
        // Generate several keypairs and confirm they all validate
        for _ in 0..10 {
            let (pk, sk) = sign::gen_keypair();
            let pk_b64 = base64::encode(pk);
            let sk_b64 = base64::encode(&sk);
            assert!(
                validate_keypair(&pk_b64, &sk_b64).is_ok(),
                "freshly generated keypair should always validate"
            );
        }
    }

    #[test]
    fn test_validate_keypair_swapped_pk_sk() {
        // Swapping public and secret key args should fail
        let (pk, sk) = sign::gen_keypair();
        let pk_b64 = base64::encode(pk);
        let sk_b64 = base64::encode(&sk);
        let result = validate_keypair(&sk_b64, &pk_b64);
        assert!(result.is_err(), "swapped pk/sk should fail validation");
    }

    #[test]
    fn test_validate_keypair_corrupted_sk() {
        // Take a valid keypair, flip a byte in the secret key
        let (pk, sk) = sign::gen_keypair();
        let pk_b64 = base64::encode(pk);
        let mut sk_bytes = sk[..].to_vec();
        sk_bytes[0] ^= 0xFF; // corrupt first byte
        let sk_b64 = base64::encode(&sk_bytes);
        let result = validate_keypair(&pk_b64, &sk_b64);
        assert!(result.is_err(), "corrupted secret key should fail validation");
    }

    #[test]
    fn test_validate_keypair_corrupted_pk() {
        // Take a valid keypair, flip a byte in the public key
        let (pk, sk) = sign::gen_keypair();
        let mut pk_bytes = pk[..].to_vec();
        pk_bytes[0] ^= 0xFF; // corrupt first byte
        let pk_b64 = base64::encode(&pk_bytes);
        let sk_b64 = base64::encode(&sk);
        let result = validate_keypair(&pk_b64, &sk_b64);
        assert!(result.is_err(), "corrupted public key should fail validation");
    }
}
