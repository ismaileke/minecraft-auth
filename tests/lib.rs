#[cfg(test)]
mod tests {
    use minecraft_auth::bedrock;
    use tokio;

    #[tokio::test]
    async fn test_work_function() {
        let mut bedrock = bedrock::new("1.21.2".to_string(), false);
        if bedrock.auth().await {
            let chain = bedrock.get_chain_data();
            let _pkey = bedrock.get_pkey().unwrap();
            println!("Chain 1: {}\n\nChain 2: {}", chain[0], chain[1]);
        }
    }
}
