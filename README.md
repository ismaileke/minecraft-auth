# minecraft-auth
Provides the connections needed for the server.

## Usage

📄Cargo.toml
```css
[dependencies]
// OpenSSL ❌ (default and recommended)
minecraft-auth = { git = "https://github.com/ismaileke/minecraft-auth.git", branch = "master" }
// OpenSSL ✅
minecraft-auth = { git = "https://github.com/ismaileke/minecraft-auth.git", branch = "master", default-features = false, features = ["openssl"] } }
```


📄main.rs
```rust
use minecraft_auth::bedrock;

#[tokio::main]
async fn main() {
    // OpenSSL ❌ (default and recommended)
    let mut bedrock = bedrock::new("1.21.130".to_string(), false); // (client version, debug mode)

    bedrock.set_auth_callback(|code, url| {
        println!("You can log in with the code {} at {}", code, url);
    });

    bedrock.auth().await;

    let chain = bedrock.get_chain_data();
    let _signing_key = bedrock.get_signing_key_384().unwrap(); // When sending the Login Packet, we will need this
    let signed_token = bedrock.get_signed_token(); // When sending the Login Packet, we will need this

    println!("Chain 1: {}\n\nChain 2: {}\n\nSigned Token: {:?}", chain[0], chain[1]);
    
    // OpenSSL ✅
    let mut bedrock = bedrock::new("1.21.130".to_string(), false); // (client version, debug mode)

    bedrock.set_auth_callback(|code, url| { // If you want to use the code and link and do something:
        println!("You can log in with the code {} at {}", code, url);
    });

    bedrock.auth().await;

    let chain = bedrock.get_chain_data();
    let ec_key = bedrock.get_ec_key().unwrap(); // When sending the Login Packet, we will need this
    let signed_token = bedrock.get_signed_token(); // When sending the Login Packet, we will need this
    println!("Chain 1: {}\nChain 2: {}", chain[0], chain[1]);
    
}
```



## 📍 NOTE
Only Bedrock support for now
