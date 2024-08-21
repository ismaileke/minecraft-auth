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
    let mut bedrock = bedrock::new(false); // debug = false
    if bedrock.auth().await {
        let chain = bedrock.get_chain_data();
        println!("Chain 1: {}\nChain 2: {}", chain[0], chain[1]);
    }
}
```

## 📍 NOTE
It is still in development.