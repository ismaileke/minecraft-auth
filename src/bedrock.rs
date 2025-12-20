use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{DateTime, Utc};
use p256::{
    ecdsa::{signature::DigestSigner, Signature, SigningKey},
    elliptic_curve::rand_core::OsRng, EncodedPoint as EncodedPoint256,
    PublicKey,
};
use p384::{
    ecdsa::SigningKey as SigningKey384,
    EncodedPoint as EncodedPoint384, PublicKey as PublicKey384,
};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use reqwest::{Client, Error, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::process::exit;
use std::string::String;
use uuid::Uuid;

pub struct Bedrock {
    client: Client,
    client_id: &'static str,
    client_version: String,
    chain_data: Vec<String>,
    signing_key_384: Option<SigningKey384>,
    debug: bool,
    auth_callback: Option<Box<dyn Fn(&str, &str) + Send + Sync>>,
    mc_token_valid_until: Option<DateTime<Utc>>,
    mc_token: Option<String>,
    signed_token: Option<String>,
    playfab_session_ticket: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct ErrorResponse {
    error: String,
    error_description: String,
}

#[derive(Deserialize)]
pub struct OAuth20Connect {
    device_code: String,
    expires_in: u64,
    interval: u64,
    user_code: String,
    verification_uri: String,
}

#[derive(Deserialize)]
pub struct OAuth20Token {
    token_type: String,
    expires_in: u64,
    scope: String,
    access_token: String,
    refresh_token: String,
    user_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Claims {
    issue_instant: String,
    not_after: String,
    token: String,
    display_claims: Value
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TokenData {
    title_token: Claims,
    user_token: Claims,
    authorization_token: Claims,
    web_page: String,
}

#[derive(Deserialize)]
pub struct ChainData {
    chain: Value
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct PlayFabLoginRequest {
    title_id: String,
    create_account: bool,
    xbox_token: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PlayFabLoginData {
    session_ticket: String,
    play_fab_id: String,
    entity_token: Option<Value>,
}

#[derive(Deserialize)]
struct PlayFabLoginResponse {
    data: PlayFabLoginData,
}

#[derive(Deserialize)]
struct SessionStartResult {
    result: SessionStartInner,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionStartInner {
    authorization_header: String,
    valid_until: String,
    issued_at: String,
}

#[derive(Deserialize)]
struct MultiplayerStartResult {
    result: MultiplayerStartInner,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MultiplayerStartInner {
    signed_token: String,
    valid_until: String,
    issued_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct SessionStartRequestDevice {
    application_type: &'static str,
    capabilities: Vec<String>,
    game_version: String,
    id: String,
    is_preview: bool,
    memory: String,
    platform: String,
    play_fab_title_id: String,
    store_platform: String,
    treatment_overrides: Option<Value>,
    #[serde(rename = "type")]
    typ: String,
}

#[derive(Serialize)]
struct SessionStartRequestUser {
    language: String,
    language_code: String,
    region_code: String,
    token: String,
    token_type: String,
}

#[derive(Serialize)]
struct SessionStartRequest {
    device: SessionStartRequestDevice,
    user: SessionStartRequestUser,
}

pub fn new(client_version: String, debug: bool) -> Bedrock {
    let client = Client::new();
    Bedrock {
        client,
        client_id: "0000000048183522",
        client_version,
        chain_data: vec!["".to_string(), "".to_string()],
        signing_key_384: None,
        debug,
        auth_callback: None,
        mc_token_valid_until: None,
        mc_token: None,
        signed_token: None,
        playfab_session_ticket: None,
    }
}

impl Bedrock {
    pub fn set_auth_callback<F>(&mut self, callback: F)
    where
        F: Fn(&str, &str) + Send + Sync + 'static,
    {
        self.auth_callback = Some(Box::new(callback));
    }

    pub async fn auth(&mut self) -> bool {
        // Create P-256 key pair
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key = PublicKey::from(verifying_key);

        // Take the public key as an encoded point
        let encoded_point = EncodedPoint256::from(public_key);
        let public_key_bytes = encoded_point.as_bytes();

        // Separate the X and Y coordinates (uncompressed format: 0x04 || X || Y)
        let x_bytes = &public_key_bytes[1..33];
        let y_bytes = &public_key_bytes[33..65];

        let x_b64 = BASE64.encode(x_bytes);
        let y_b64 = BASE64.encode(y_bytes);

        let mut device_code = String::new();
        let mut access_token = String::new();
        let mut device_token = String::new();
        let mut authorization_token = String::new();
        let mut xbox_user_id = String::new();
        let mut user_token = String::new();

        match self.oauth20_connect().await {
            Ok((oauth_connect, error_response)) => {
                if let Some(oauth_conn) = oauth_connect {
                    if let Some(ref callback) = self.auth_callback {
                        callback(&oauth_conn.user_code, &oauth_conn.verification_uri);
                    }
                    if self.debug {
                        println!(
                            "You can log in with the code {} at {}",
                            oauth_conn.user_code, oauth_conn.verification_uri
                        );
                    }
                    device_code = oauth_conn.device_code;
                }
                if let Some(err) = error_response {
                    println!(
                        "OAuth 2.0 Connect -> Error: {}, Error Description: {}",
                        err.error, err.error_description
                    );
                }
            }
            Err(e) => {
                println!("\n\nOAuth2.0 Connect General Error: {:?}", e);
            }
        }

        loop {
            match self.oauth20_token(device_code.clone()).await {
                Ok((oauth_token, error_response)) => {
                    if let Some(token) = oauth_token {
                        access_token = token.access_token;
                        break;
                    }

                    if let Some(err) = error_response {
                        if err.error == "authorization_pending".to_string() {
                            continue;
                        }
                        println!("OAuth 2.0 Token -> Error: {}, Error Description: {}", err.error, err.error_description);
                        break;
                    }
                }
                Err(e) => {
                    println!("\n\nOAuth2.0 Token General Error: {:?}", e);
                    break;
                }
            }
        }

        match self.device_auth(&signing_key, x_b64.clone(), y_b64.clone()).await {
            Ok((device_auth, error_response)) => {
                if let Some(auth) = device_auth {
                    device_token = auth.token;
                    if self.debug {
                        println!("Device Auth Connect Successful");
                    }
                }
                if let Some(err) = error_response {
                    println!(
                        "Device Auth -> Error: {}, Error Description: {}",
                        err.error, err.error_description
                    );
                }
            }
            Err(e) => {
                println!("\n\nDevice Auth General Error: {:?}", e);
            }
        }

        match self.sisu_authorize(&signing_key, access_token, device_token.clone(), x_b64.clone(), y_b64.clone()).await {
            Ok((token_data, error_response)) => {
                if let Some(sisu) = token_data {
                    user_token = sisu.user_token.token;
                    authorization_token = sisu.authorization_token.token;
                    xbox_user_id = sisu.user_token.display_claims
                        .get("xui")
                        .and_then(|v| v.get(0))
                        .and_then(|v| v.get("uhs"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("UHS not found")
                        .to_string();
                    if xbox_user_id == "UHS not found".to_string() {
                        exit(1);
                    }
                    if self.debug {
                        println!("Sisu Authorize Successful");
                    }
                }
                if let Some(err) = error_response {
                    println!(
                        "Sisu Authorize -> Error: {}, Error Description: {}",
                        err.error, err.error_description
                    );
                }
            }
            Err(e) => {
                println!("\n\nSisu Authorize General Error: {:?}", e);
            }
        }

        match self.minecraft_authentication(xbox_user_id.clone(), authorization_token.clone()).await {
            Ok((chain_data, error_response)) => {
                if let Some(chain) = chain_data {
                    if let Some(arr) = chain.chain.as_array() {
                        for (index, item) in arr.iter().enumerate() {
                            if let Some(jwt) = item.as_str() {
                                self.chain_data[index] = jwt.to_string();
                            } else {
                                panic!("Item is not a string");
                            }
                        }
                    } else {
                        panic!("Expected a JSON array");
                    }
                    if self.debug {
                        println!("Minecraft Authorization Successful");
                    }
                }
                if let Some(err) = error_response {
                    panic!(
                        "Minecraft Authorization -> Error: {}, Error Description: {}",
                        err.error, err.error_description
                    );
                }
            }
            Err(e) => {
                panic!("\n\nMinecraft Authorization General Error: {:?}", e);
            }
        }

        let playfab_xsts_token = match self.get_xsts_token_for_playfab(user_token).await {
            Ok(token) => token,
            Err(e) => {
                println!("PlayFab XSTS Token Error: {:?}", e);
                return false;
            }
        };

        match self.playfab_login(&playfab_xsts_token.0, &playfab_xsts_token.1).await {
            Ok(_) => {
                if self.debug {
                    println!("PlayFab Login Successful");
                }
            }
            Err(e) => {
                println!("PlayFab Login Error: {:?}", e);
                return false;
            }
        }

        let device_id = Uuid::new_v4().to_string();
        const PLAYFAB_TITLE_ID: &str = "20CA2";

        match self.session_start(PLAYFAB_TITLE_ID, &device_id).await {
            Ok(_) => {
                if self.debug {
                    println!("Session Start Successful");
                }
            }
            Err(e) => {
                println!("Session Start Error: {:?}", e);
                return false;
            }
        }

        if let Some(ref signing_key) = self.signing_key_384 {
            let verifying_key = signing_key.verifying_key();
            let public_key = PublicKey384::from(verifying_key);
            let encoded_point = EncodedPoint384::from(public_key);

            // Convert to SubjectPublicKeyInfo format
            let public_key_der = spki_encode_p384(&encoded_point);
            let public_key_base64 = BASE64.encode(&public_key_der);

            match self.multiplayer_session_start(&public_key_base64).await {
                Ok(_) => {
                    if self.debug {
                        println!("Multiplayer Session Start Successful");
                    }
                }
                Err(e) => {
                    println!("Multiplayer Session Start Error: {:?}", e);
                    return false;
                }
            }
        }

        true
    }

    pub fn get_chain_data(&self) -> Vec<String> {
        self.chain_data.to_vec()
    }

    pub fn get_signing_key_384(&self) -> Option<SigningKey384> {
        self.signing_key_384.clone()
    }

    pub fn get_signed_token(&self) -> Option<String> {
        self.signed_token.clone()
    }

    async fn oauth20_connect(&self) -> Result<(Option<OAuth20Connect>, Option<ErrorResponse>), Error> {
        let mut body = HashMap::new();
        body.insert("client_id", self.client_id);
        body.insert("scope", "service::user.auth.xboxlive.com::MBI_SSL");
        body.insert("response_type", "device_code");

        let response = self
            .client
            .post("https://login.live.com/oauth20_connect.srf")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .form(&body)
            .send()
            .await?;

        match response.status() {
            StatusCode::OK => {
                let oauth: OAuth20Connect = response.json().await?;
                if self.debug {
                    println!("*-- OAuth 2.0 Connect --->");
                    println!("Device Code: {}", oauth.device_code);
                    println!("Expires In: {}", oauth.expires_in);
                    println!("Interval: {}", oauth.interval);
                    println!("User Code: {}", oauth.user_code);
                    println!("Verification URI: {}", oauth.verification_uri);
                    println!("<------------------------*");
                }
                Ok((Some(oauth), None))
            }
            StatusCode::BAD_REQUEST => {
                let err_response: ErrorResponse = response.json().await?;
                Ok((None, Some(err_response)))
            }
            StatusCode::UNAUTHORIZED => {
                let err = ErrorResponse {
                    error: "HTTP 401".to_string(),
                    error_description: "Unauthorized".to_string(),
                };
                Ok((None, Some(err)))
            }
            StatusCode::FORBIDDEN => {
                let err = ErrorResponse {
                    error: "HTTP 403".to_string(),
                    error_description: "Forbidden".to_string(),
                };
                Ok((None, Some(err)))
            }
            _ => {
                let err = ErrorResponse {
                    error: response.status().to_string(),
                    error_description: "".to_string(),
                };
                Ok((None, Some(err)))
            }
        }
    }

    async fn oauth20_token(&self, device_code: String) -> Result<(Option<OAuth20Token>, Option<ErrorResponse>), Error> {
        let mut body = HashMap::new();
        body.insert("client_id", self.client_id);
        body.insert("grant_type", "urn:ietf:params:oauth:grant-type:device_code");
        body.insert("device_code", &*device_code);

        let response = self
            .client
            .post("https://login.live.com/oauth20_token.srf")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .form(&body)
            .send()
            .await?;

        match response.status() {
            StatusCode::OK => {
                let oauth: OAuth20Token = response.json().await?;
                if self.debug {
                    println!("*-- OAuth 2.0 Token --->");
                    println!("Token Type: {}", oauth.token_type);
                    println!("Expires In: {}", oauth.expires_in);
                    println!("Scope: {}", oauth.scope);
                    println!("Access Token: {}", oauth.access_token);
                    println!("Refresh Token: {}", oauth.refresh_token);
                    println!("User ID: {}", oauth.user_id);
                    println!("<----------------------*");
                }
                Ok((Some(oauth), None))
            }
            StatusCode::BAD_REQUEST => {
                let err_response: ErrorResponse = response.json().await?;
                Ok((None, Some(err_response)))
            }
            _ => {
                let err = ErrorResponse {
                    error: response.status().to_string(),
                    error_description: "".to_string(),
                };
                Ok((None, Some(err)))
            }
        }
    }

    async fn device_auth(&self, signing_key: &SigningKey, x_b64: String, y_b64: String) -> Result<(Option<Claims>, Option<ErrorResponse>), Error> {
        let body = json!({
            "Properties": {
                "AuthMethod": "ProofOfPossession",
                "DeviceType": "Android",
                "Id": Uuid::new_v4().to_string(),
                "ProofKey": {
                    "crv": "P-256",
                    "alg": "ES256",
                    "use": "sig",
                    "kty": "EC",
                    "x": x_b64,
                    "y": y_b64
                },
                "Version": "10"
            },
            "RelyingParty": "http://auth.xboxlive.com",
            "TokenType": "JWT"
        });

        let mut headers = HeaderMap::new();
        headers.insert("x-xbl-contract-version", HeaderValue::from_static("1"));

        let body_str = body.to_string();
        let signature = sign("/device/authenticate", &body_str, None, signing_key);
        headers.insert("Signature", HeaderValue::from_str(&signature).unwrap());

        let response = self
            .client
            .post("https://device.auth.xboxlive.com/device/authenticate")
            .headers(headers)
            .json(&body)
            .send()
            .await?;

        match response.status() {
            StatusCode::OK => {
                let claim: Claims = response.json().await?;
                if self.debug {
                    println!("*-- Device Auth --->");
                    println!("Issue Instant: {}", claim.issue_instant);
                    println!("Not After: {}", claim.not_after);
                    println!("Token: {}", claim.token);
                    println!("*------------------>");
                }
                Ok((Some(claim), None))
            }
            _ => {
                let err = ErrorResponse {
                    error: response.status().to_string(),
                    error_description: "".to_string(),
                };
                Ok((None, Some(err)))
            }
        }
    }

    async fn sisu_authorize(&self, signing_key: &SigningKey, access_token: String, device_token: String, x_b64: String, y_b64: String) -> Result<(Option<TokenData>, Option<ErrorResponse>), Error> {
        let body = json!({
            "AccessToken": format!("t={}", access_token),
            "AppId": self.client_id,
            "DeviceToken": device_token,
            "Sandbox": "RETAIL",
            "UseModernGamertag": true,
            "SiteName": "user.auth.xboxlive.com",
            "RelyingParty": "https://multiplayer.minecraft.net/",
            "ProofKey": {
                "crv": "P-256",
                "alg": "ES256",
                "use": "sig",
                "kty": "EC",
                "x": x_b64,
                "y": y_b64
            }
        });

        let mut headers = HeaderMap::new();
        headers.insert("x-xbl-contract-version", HeaderValue::from_static("1"));

        let body_str = body.to_string();
        let signature = sign("/authorize", &body_str, None, signing_key);
        headers.insert("Signature", HeaderValue::from_str(&signature).unwrap());

        let response = self
            .client
            .post("https://sisu.xboxlive.com/authorize")
            .headers(headers)
            .json(&body)
            .send()
            .await?;

        match response.status() {
            StatusCode::OK => {
                let token_data: TokenData = response.json().await?;
                if self.debug {
                    println!("*-- Sisu Authorize --->");
                    println!("Title Token: {}", token_data.title_token.token);
                    println!("User Token: {}", token_data.user_token.token);
                    println!("*-------------------->");
                }
                Ok((Some(token_data), None))
            }
            _ => {
                let err = ErrorResponse {
                    error: response.status().to_string(),
                    error_description: "".to_string(),
                };
                Ok((None, Some(err)))
            }
        }
    }

    async fn minecraft_authentication(&mut self, xbox_user_id: String, authorization_token: String) -> Result<(Option<ChainData>, Option<ErrorResponse>), Error> {
        // Create P-384 key pair again
        let signing_key = SigningKey384::random(&mut OsRng);
        self.signing_key_384 = Some(signing_key.clone());

        let verifying_key = signing_key.verifying_key();
        let public_key = PublicKey384::from(verifying_key);
        let encoded_point = EncodedPoint384::from(public_key);

        // Convert to SubjectPublicKeyInfo format
        let public_key_der = spki_encode_p384(&encoded_point);
        let public_key_base64 = BASE64.encode(&public_key_der);

        let body = json!({
            "identityPublicKey": public_key_base64,
        });

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        headers.insert(USER_AGENT, "MCPE/Android".parse().unwrap());
        headers.insert("Client-Version", HeaderValue::from_str(&self.client_version).unwrap());
        headers.insert(AUTHORIZATION, format!("XBL3.0 x={};{}", xbox_user_id, authorization_token).parse().unwrap());

        let response = self
            .client
            .post("https://multiplayer.minecraft.net/authentication")
            .headers(headers)
            .json(&body)
            .send()
            .await?;

        match response.status() {
            StatusCode::OK => {
                let chain_data: ChainData = response.json().await?;
                if self.debug {
                    println!("*-- Minecraft Authorization --->");
                    println!("Chain: {}", chain_data.chain);
                    println!("*------------------------------>");
                }
                Ok((Some(chain_data), None))
            }
            _ => {
                let err = ErrorResponse {
                    error: response.status().to_string(),
                    error_description: "".to_string(),
                };
                Ok((None, Some(err)))
            }
        }
    }

    async fn get_xsts_token_for_playfab(&self, user_token: String) -> Result<(String, String), Error> {
        let body = json!({
            "Properties": {
                "SandboxId": "RETAIL",
                "UserTokens": [user_token]
            },
            "RelyingParty": "https://b980a380.minecraft.playfabapi.com/",
            "TokenType": "JWT"
        });

        let response = self
            .client
            .post("https://xsts.auth.xboxlive.com/xsts/authorize")
            .header(CONTENT_TYPE, "application/json")
            .header("x-xbl-contract-version", "1")
            .json(&body)
            .send()
            .await?;

        let status = response.status();
        let body_text = response.text().await.unwrap_or_default();

        if status.is_success() {
            let claim: Claims = serde_json::from_str(&body_text)
                .expect("Failed to parse XSTS response");
            Ok((claim.token, claim.display_claims
                .get("xui")
                .and_then(|v| v.get(0))
                .and_then(|v| v.get("uhs"))
                .and_then(|v| v.as_str())
                .unwrap_or("UHS not found")
                .to_string()))
        } else {
            panic!("XSTS failed: {}", body_text);
        }
    }

    async fn playfab_login(&mut self, xsts_token: &str, uhs: &str) -> Result<(), Error> {
        let url = "https://20ca2.playfabapi.com/Client/LoginWithXbox";
        let xbox_token = format!("XBL3.0 x={};{}", uhs, xsts_token);

        let body = PlayFabLoginRequest {
            title_id: String::from("20CA2"),
            create_account: true,
            xbox_token,
        };

        let resp = self
            .client
            .post(url)
            .header(CONTENT_TYPE, "application/json")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();

        if status.is_success() {
            let parsed: PlayFabLoginResponse = serde_json::from_str(&body_text)
                .expect("Failed to parse PlayFab response");
            self.playfab_session_ticket = Some(parsed.data.session_ticket.clone());

            if self.debug {
                println!("PlayFab Login Successful");
            }
            Ok(())
        } else {
            panic!("PlayFab login failed: {}", body_text);
        }
    }

    async fn session_start(&mut self, playfab_title_id: &str, device_id: &str) -> Result<(), Error> {
        let url = "https://authorization.franchise.minecraft-services.net/api/v1.0/session/start";

        let session_ticket = self.playfab_session_ticket.clone()
            .expect("No PlayFab session ticket");

        let device = SessionStartRequestDevice {
            application_type: "MinecraftPE",
            capabilities: vec![],
            game_version: self.client_version.clone(),
            id: device_id.to_string(),
            is_preview: false,
            memory: String::from("1024"),
            platform: String::from("Windows10"),
            play_fab_title_id: playfab_title_id.to_string(),
            store_platform: String::from("uwp.store"),
            treatment_overrides: None,
            typ: String::from("Windows10"),
        };

        let user = SessionStartRequestUser {
            language: String::from("en"),
            language_code: String::from("en-US"),
            region_code: String::from("US"),
            token: session_ticket,
            token_type: String::from("PlayFab"),
        };

        let body = SessionStartRequest { device, user };

        let resp = self
            .client
            .post(url)
            .header(CONTENT_TYPE, "application/json")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();

        if status.is_success() {
            let parsed: SessionStartResult = serde_json::from_str(&body_text).unwrap();
            let auth_header = parsed.result.authorization_header;
            let valid_until = parsed.result.valid_until;

            if let Ok(dt) = DateTime::parse_from_rfc3339(&valid_until) {
                self.mc_token_valid_until = Some(dt.with_timezone(&Utc));
            }

            self.mc_token = Some(auth_header);
            Ok(())
        } else {
            panic!("Session start failed: {}", body_text);
        }
    }

    async fn multiplayer_session_start(&mut self, public_key_base64: &str) -> Result<(), Error> {
        let url = "https://authorization.franchise.minecraft-services.net/api/v1.0/multiplayer/session/start";

        let mc_token = self.mc_token.clone().expect("No MC token");

        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&mc_token).unwrap());
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let body = json!({ "publicKey": public_key_base64 });

        let resp = self
            .client
            .post(url)
            .headers(headers)
            .json(&body)
            .send()
            .await?;

        if resp.status().is_success() {
            let parsed: MultiplayerStartResult = resp.json().await?;
            self.signed_token = Some(parsed.result.signed_token);

            if self.debug {
                println!("Multiplayer session start successful");
            }
            Ok(())
        } else {
            let body_text = resp.text().await.unwrap_or_default();
            panic!("Multiplayer session start failed: {}", body_text);
        }
    }
}

fn sign(endpoint: &str, body: &str, authorization: Option<&str>, signing_key: &SigningKey) -> String {
    let current_time = (Utc::now().timestamp() as u64 + 11_644_473_600) * 10_000_000;

    let mut buf = Vec::new();

    // policy (0,0,0,1) + null
    buf.extend_from_slice(&[0, 0, 0, 1, 0]);

    // timestamp + null
    buf.extend_from_slice(&current_time.to_be_bytes());
    buf.push(0);

    // method + null
    buf.extend_from_slice(b"POST");
    buf.push(0);

    // path (+query) + null
    buf.extend_from_slice(endpoint.as_bytes());
    buf.push(0);

    // authorization header + null
    if let Some(auth) = authorization {
        buf.extend_from_slice(auth.as_bytes());
    }
    buf.push(0);

    // body + null
    buf.extend_from_slice(body.as_bytes());
    buf.push(0);

    // SHA256
    let mut hasher = Sha256::new();
    hasher.update(&buf);

    // ECDSA sign (NO DOUBLE HASH)
    let signature: Signature = signing_key.sign_digest(hasher);

    let r = signature.r().to_bytes();
    let s = signature.s().to_bytes();

    let mut r_pad = [0u8; 32];
    let mut s_pad = [0u8; 32];
    r_pad[32 - r.len()..].copy_from_slice(&r);
    s_pad[32 - s.len()..].copy_from_slice(&s);

    // final payload
    let mut result = Vec::new();
    result.extend_from_slice(&[0, 0, 0, 1]);
    result.extend_from_slice(&current_time.to_be_bytes());
    result.extend_from_slice(&r_pad);
    result.extend_from_slice(&s_pad);

    BASE64.encode(result)
}

// Convert the P-384 public key to SubjectPublicKeyInfo (SPKI) format
fn spki_encode_p384(encoded_point: &EncodedPoint384) -> Vec<u8> {
    // OID for id-ecPublicKey: 1.2.840.10045.2.1
    let ec_public_key_oid = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

    // OID for secp384r1: 1.3.132.0.34
    let secp384r1_oid = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];

    let point_bytes = encoded_point.as_bytes();

    let mut spki = Vec::new();

    // SEQUENCE
    spki.push(0x30);

    // Algorithm Identifier SEQUENCE content
    let mut algorithm_identifier = Vec::new();
    algorithm_identifier.extend_from_slice(&ec_public_key_oid);
    algorithm_identifier.extend_from_slice(&secp384r1_oid);

    // Subject Public Key (BIT STRING)
    let mut subject_public_key = Vec::new();
    subject_public_key.push(0x03); // BIT STRING
    subject_public_key.push((point_bytes.len() + 1) as u8);
    subject_public_key.push(0x00); // Unused bits
    subject_public_key.extend_from_slice(point_bytes);

    // Algorithm Identifier (SEQUENCE)
    let mut algo_seq = Vec::new();
    algo_seq.push(0x30); // SEQUENCE
    algo_seq.push(algorithm_identifier.len() as u8);
    algo_seq.extend_from_slice(&algorithm_identifier);

    let total_len = algo_seq.len() + subject_public_key.len();

    if total_len < 128 {
        spki.push(total_len as u8);
    } else {
        spki.push(0x81);
        spki.push(total_len as u8);
    }

    spki.extend_from_slice(&algo_seq);
    spki.extend_from_slice(&subject_public_key);

    spki
}