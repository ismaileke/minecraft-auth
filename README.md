# minecraft-auth
Provides the connections needed for the server.

## Usage

📄Cargo.toml
```css
[dependencies]
minecraft-auth = { git = "https://github.com/ismaileke/minecraft-auth.git", branch = "master" }
```


📄main.rs
```rust
use minecraft_auth::bedrock;

#[tokio::main]
async fn main() {
    let mut bedrock = bedrock::new("1.21.80".to_string(), false); // (client version, debug mode)

    bedrock.set_auth_callback(|code, url| { // If you want to use the code and link and do something:
        println!("Code: {} URL: {}", code, url);
    });

    bedrock.auth().await;

    let chain = bedrock.get_chain_data();
    let ec_key = bedrock.get_ec_key().unwrap(); // When sending the Login Packet we will need this
    println!("Chain 1: {}\nChain 2: {}", chain[0], chain[1]);
    
}
```



## 📍 NOTE
Only Bedrock support for now
