use chrono::{DateTime, Utc};
use openssl::base64::{decode_block, encode_block};
use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey, PointConversionForm};
use openssl::ecdsa::EcdsaSig;
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use reqwest::{Client, Error, StatusCode};
use serde::de::StdError;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::process::exit;
use std::string::String;
use uuid::Uuid;

pub struct Bedrock {
    client: Client,
    client_id: &'static str,
    client_version: String,
    chain_data: Vec<String>,
    ec_key: Option<EcKey<Private>>,
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
    device_token: String,
    title_token: Claims,
    user_token: Claims,
    authorization_token: Claims,
    web_page: String,
    sandbox: String,
    use_modern_gamertag: bool,
    flow: String,
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
    #[serde(rename = "PlayFabId")]
    playfab_id: String,
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
#[serde(rename_all = "PascalCase")]
struct SessionStartInner {
    #[serde(rename = "authorizationHeader")]
    authorization_header: String,
    #[serde(rename = "validUntil")]
    valid_until: String,
    #[serde(rename = "issuedAt")]
    issued_at: String,
}

#[derive(Deserialize)]
struct MultiplayerStartResult {
    result: MultiplayerStartInner,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct MultiplayerStartInner {
    #[serde(rename = "signedToken")]
    signed_token: String,
    #[serde(rename = "validUntil")]
    valid_until: String,
    #[serde(rename = "issuedAt")]
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
        ec_key: None,
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
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("EC Group Error");
        let ec_key = EcKey::generate(&group).expect("Private Key Error");
        let key = PKey::from_ec_key(ec_key.clone()).expect("PKey Error");
        let mut ctx = BigNumContext::new().expect("BigNumContext Error");
        //println!("Private Key (PEM):\n{}", String::from_utf8_lossy(&private_key_pem));

        let public_key_bytes = ec_key.public_key().to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx).expect("Public Key Error");
        let (x_bytes, y_bytes) = public_key_bytes.split_at(33);
        let x_b64 = encode_block(&x_bytes[1..]);
        let y_b64 = encode_block(y_bytes);

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

        match self.device_auth(key.clone(), x_b64.clone(), y_b64.clone()).await {
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

        match self.sisu_authorize(key.clone(), access_token, device_token.clone(), x_b64.clone(), y_b64.clone()).await {
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
                        exit("UHS not found".parse().unwrap());
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


        // get XSTS token for PlayFab
        let playfab_xsts_token = match self.get_xsts_token_for_playfab(user_token).await {
            Ok(token) => token,
            Err(e) => {
                println!("PlayFab XSTS Token Error: {:?}", e);
                return false;
            }
        };

        // PlayFab Login
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

        // Session Start
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

        // Multiplayer Session Start
        if let Some(ref ec_key) = self.ec_key {
            let public_key_pem = ec_key.public_key_to_pem().expect("Public Key PEM Error");
            let public_key_der = pem_to_der(&public_key_pem).expect("Public Key Der Error");
            let public_key_base64 = encode_block(&public_key_der);

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

        false
    }

    pub fn get_chain_data(&self) -> Vec<String> {
        self.chain_data.to_vec()
    }

    pub fn get_ec_key(&self) -> Option<EcKey<Private>> {
        self.ec_key.clone()
    }

    pub fn get_signed_token(&self) -> Option<String> {
        self.signed_token.clone()
    }

    pub async fn oauth20_connect(&self) -> Result<(Option<OAuth20Connect>, Option<ErrorResponse>), Error> {
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

    pub async fn oauth20_token(&self, device_code: String) -> Result<(Option<OAuth20Token>, Option<ErrorResponse>), Error> {
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

    pub async fn device_auth(&self, ec_key: PKey<Private>, x_b64: String, y_b64: String) -> Result<(Option<Claims>, Option<ErrorResponse>), Error> {
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
        match sign("/device/authenticate", &body_str, &ec_key) {
            Ok(signature) => {
                match HeaderValue::from_str(&signature) {
                    Ok(header_value) => {
                        headers.insert("Signature", header_value);
                    }
                    Err(e) => eprintln!("Failed to create HeaderValue: {}", e),
                }
            }
            Err(e) => eprintln!("Signature creation failed: {}", e),
        }

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
                    println!("Display Claims -> XDI -> DID & DCS: {}", claim.display_claims.to_string()); // You don't need that
                    println!("*------------------>");
                }
                Ok((Some(claim), None))
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

    pub async fn sisu_authorize(&self, ec_key: PKey<Private>, access_token: String, device_token: String, x_b64: String, y_b64: String) -> Result<(Option<TokenData>, Option<ErrorResponse>), Error> {
        let body = json!({
            "AccessToken": format!("t={}", access_token),
            "AppId": self.client_id,
            "deviceToken": device_token,
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
        match sign("/authorize", &body_str, &ec_key) {
            Ok(signature) => {
                match HeaderValue::from_str(&signature) {
                    Ok(header_value) => {
                        headers.insert("Signature", header_value);
                    }
                    Err(e) => eprintln!("Failed to create HeaderValue: {}", e),
                }
            }
            Err(e) => eprintln!("Signature creation failed: {}", e),
        }

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
                    println!("Device Token: {}", token_data.device_token);
                    println!("Title Token (Just Token): {}", token_data.title_token.token);
                    println!("User Token (Just Token): {}", token_data.user_token.token);
                    println!("Authorization Token (Just Token): {}", token_data.authorization_token.token);
                    println!("Web Page: {}", token_data.web_page);
                    println!("Sandbox: {}", token_data.sandbox);
                    println!("User Modern GamerTag: {}", token_data.use_modern_gamertag);
                    println!("Flow: {}", token_data.flow);
                    println!("*-------------------->");
                }
                Ok((Some(token_data), None))
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

    pub async fn minecraft_authentication(&mut self, xbox_user_id: String, authorization_token: String) -> Result<(Option<ChainData>, Option<ErrorResponse>), Error> {
        let group = EcGroup::from_curve_name(Nid::SECP384R1).expect("EC Group Error");
        let ec_key = EcKey::generate(&group).expect("Private Key Error");
        //let pkey = PKey::from_ec_key(ec_key.clone()).expect("PKey Error");
        self.ec_key = Some(ec_key.clone());

        let public_key_pem = ec_key.public_key_to_pem().expect("Public Key PEM Error");
        let public_key_der = pem_to_der(&public_key_pem).expect("Public Key Der Error");
        let public_key_base64 = encode_block(&public_key_der);

        let body = json!({
            "identityPublicKey": public_key_base64,
        });

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        headers.insert(USER_AGENT, "MCPE/Android".parse().unwrap());
        headers.insert("Client-Version", HeaderValue::from_str(self.client_version.as_str()).unwrap());
        headers.insert(AUTHORIZATION, format!("XBL3.0 x={};{}", xbox_user_id, authorization_token).as_str().parse().unwrap());

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

    pub async fn get_xsts_token_for_playfab(&self, user_token: String) -> Result<(String, String), Error> {
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

        if self.debug {
            println!("\n=== XSTS FOR PLAYFAB ===");
            println!("Status: {}", status);
            println!("Response: {}", &body_text[..200.min(body_text.len())]);
            println!("========================\n");
        }

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

    pub async fn playfab_login(&mut self, xsts_token: &str, uhs: &str) -> Result<(), Error> {
        let url = "https://20ca2.playfabapi.com/Client/LoginWithXbox";

        // PlayFab token formatı: XBL3.0 x=<uhs>;<xsts_token>
        let xbox_token = format!("XBL3.0 x={};{}", uhs, xsts_token);

        let body = PlayFabLoginRequest {
            title_id: String::from("20CA2"),
            create_account: true,
            xbox_token,
        };

        if self.debug {
            println!("\n=== PLAYFAB LOGIN ===");
            println!("Xbox User ID: {}", uhs);
            println!("XSTS Token (first 50): {}", &xsts_token[..50.min(xsts_token.len())]);
        }

        let resp = self
            .client
            .post(url)
            .header(CONTENT_TYPE, "application/json")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();

        if self.debug {
            println!("Status: {}", status);
            println!("Response: {}", body_text);
            println!("====================\n");
        }

        if status.is_success() {
            let parsed: PlayFabLoginResponse = serde_json::from_str(&body_text)
                .expect("Failed to parse PlayFab response");
            self.playfab_session_ticket = Some(parsed.data.session_ticket.clone());

            if self.debug {
                println!("PlayFab Login Successful");
                println!("Session Ticket: {}", parsed.data.session_ticket);
            }
            Ok(())
        } else {
            panic!("PlayFab login failed: {}", body_text);
        }
    }

    pub async fn session_start(&mut self, playfab_title_id: &str, device_id: &str) -> Result<(), Error> {
        let url = "https://authorization.franchise.minecraft-services.net/api/v1.0/session/start";

        let session_ticket = match &self.playfab_session_ticket {
            Some(ticket) => ticket.clone(),
            None => {
                panic!("No PlayFab session ticket");
            }
        };

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

        if self.debug {
            println!("\n=== SESSION START ===");
            println!("Status: {}", status);
            println!("Response: {}", body_text);
            println!("====================\n");
        }

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

    pub async fn multiplayer_session_start(&mut self, public_key_base64: &str) -> Result<(), Error> {
        let url = "https://authorization.franchise.minecraft-services.net/api/v1.0/multiplayer/session/start";

        let mc_token = match &self.mc_token {
            Some(t) => t.clone(),
            None => {
                panic!("No MC token");
            }
        };

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


pub fn sign(endpoint: &str, body: &str, key: &PKey<Private>) -> Result<String, ErrorStack> {
    let current_time = (Utc::now().timestamp() as u64 + 11644473600) * 10000000;

    let mut buf = Vec::new();
    buf.push(0);
    buf.push(0);
    buf.push(0);
    buf.push(1);
    buf.push(0);

    buf.extend_from_slice(&current_time.to_be_bytes());
    buf.push(0);

    buf.extend_from_slice(b"POST");
    buf.push(0);

    buf.extend_from_slice(endpoint.as_bytes());
    buf.push(0);
    buf.push(0);
    buf.extend_from_slice(body.as_bytes());
    buf.push(0);

    let mut signer = Signer::new(openssl::hash::MessageDigest::sha256(), &key).expect("Signer not created");
    signer.update(&buf)?;
    let signature = signer.sign_to_vec().expect("Signature not created");

    let ecdsa = EcdsaSig::from_der(&signature)?;
    let r = ecdsa.r().to_vec();
    let s = ecdsa.s().to_vec();

    let mut result = Vec::new();
    result.push(0);
    result.push(0);
    result.push(0);
    result.push(1);
    result.extend_from_slice(&current_time.to_be_bytes());
    result.extend_from_slice(&r);
    result.extend_from_slice(&s);

    Ok(encode_block(&result))
}

pub fn pem_to_der(pem_data: &[u8]) -> Result<Vec<u8>, Box<dyn StdError>> {
    let pem_str = String::from_utf8(pem_data.to_vec())?;
    let lines: Vec<&str> = pem_str.lines().filter(|&line| !line.starts_with("-----")).collect();
    let base64_data = lines.join("");

    let der_data = decode_block(&base64_data)?;
    Ok(der_data)
}