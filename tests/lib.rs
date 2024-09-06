#[cfg(test)]
mod tests {
    use minecraft_auth::bedrock;
    use tokio;

    #[tokio::test]
    async fn test_work_function() {
        let mut bedrock = bedrock::new("1.21.2".to_string(), false);
        if bedrock.auth().await {
            let chain = bedrock.get_chain_data();
            let _ec_key = bedrock.get_ec_key().unwrap();
            println!("Chain 1: {}\n\nChain 2: {}", chain[0], chain[1]);
        }
    }
}
