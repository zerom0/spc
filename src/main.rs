mod error;

use crate::error::Error;

use anyhow::Result;
use clap::{Arg, Command};
use reqwest::{
    header::{AUTHORIZATION, CONTENT_TYPE},
    Client,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, env, time::Duration};

#[tokio::main]
async fn main() -> Result<()> {
    //env::set_var("RUST_LOG", "info");
    env_logger::init();

    let cli = Command::new(clap::crate_name!())
        .version(clap::crate_version!())
        .about(clap::crate_description!())
        .subcommand(Command::new("lock").about("Lock flap"))
        .subcommand(Command::new("unlock").about("Unlock flap"))
        .subcommand(
            Command::new("curfew")
                .about("Set curfew for flap")
                .arg(Arg::new("from").help("Lock time").required(true).index(1))
                .arg(Arg::new("to").help("Unlock time").required(true).index(2)),
        )
        .arg_required_else_help(true)
        .get_matches();

    let http_timeout = Duration::from_secs(30);
    let http_client = Client::builder()
        .timeout(http_timeout)
        .danger_accept_invalid_certs(false)
        .build()
        .expect("Building http client");

    let device_id = env::var("SPC_DEVICE_ID").expect("Missing environment variable SPC_DEVICE_ID");
    if cli.subcommand_matches("lock").is_some() {
        lock(&http_client, &device_id).await?;
    } else if cli.subcommand_matches("unlock").is_some() {
        unlock(&http_client, &device_id).await?;
    } else if let Some(matches) = cli.subcommand_matches("curfew") {
        let from = matches.get_one::<String>("from").unwrap();
        let to = matches.get_one::<String>("to").unwrap();

        curfew(&http_client, &device_id, from, to).await?;
    }
    Ok(())
}

#[derive(Deserialize)]
struct LoginResponseData {
    token: String,
}

#[derive(Deserialize)]
struct LoginResponse {
    data: LoginResponseData,
}

async fn login(http_client: &Client) -> Result<String, Error> {
    log::info!("Logging in");

    let url = "https://app.api.surehub.io/api/auth/login";
    let mut map = HashMap::new();
    let email = env::var("SPC_EMAIL").expect("Missing environment variable SPC_EMAIL");
    let password = env::var("SPC_PASSWORD").expect("Missing environment variable SPC_PASSWORD");
    map.insert("email_address", email);
    map.insert("password", password);
    map.insert("device_id", "f8e4ce0814".to_string());
    let login_response = http_client
        .post(url)
        .json(&map)
        .send()
        .await?
        .json::<LoginResponse>()
        .await?;

    log::info!("Logged in");
    Ok(login_response.data.token)
}

async fn logout(_http_client: &Client) -> Result<(), Error> {
    log::info!("Logging out");
    log::info!("Not yet implemented");
    Ok(())
}

async fn http_put_device_control(
    http_client: &Client,
    device_id: &str,
    bearer: &str,
    body: String,
) -> Result<(), Error> {
    let url = format!(
        "https://app.api.surehub.io/api/device/{}/control",
        device_id
    );
    let authorization = format!("Bearer {}", bearer);
    http_client
        .put(url)
        .header(AUTHORIZATION, authorization)
        .header(CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await?;
    Ok(())
}

async fn lock(http_client: &Client, device_id: &str) -> Result<(), Error> {
    let bearer = login(http_client).await?;

    log::info!("Locking flap");
    let body = "{ \"locking\": 1 }".to_string();
    http_put_device_control(http_client, device_id, &bearer, body).await?;
    log::info!("Locked flap");

    logout(http_client).await
}

async fn unlock(http_client: &Client, device_id: &str) -> Result<(), Error> {
    let bearer = login(http_client).await?;

    log::info!("Unlocking flap");
    let body = "{ \"locking\": 0 }".to_string();
    http_put_device_control(http_client, device_id, &bearer, body).await?;
    log::info!("Unlocked flap");

    logout(http_client).await
}

#[derive(Serialize)]
struct CurfewRequestCurfew {
    enabled: bool,
    lock_time: String,
    unlock_time: String,
}

#[derive(Serialize)]
struct CurfewRequest {
    curfew: CurfewRequestCurfew,
}

async fn curfew(http_client: &Client, device_id: &str, from: &str, to: &str) -> Result<(), Error> {
    let bearer = login(http_client).await?;

    log::info!("Setting curfew from {} to {} on flap", from, to);
    let body = format!(
        "{{ \"curfew\": {{ \"enabled\": true, \"lock_time\": \"{}\", \"unlock_time\": \"{}\" }} }}",
        from, to
    );
    http_put_device_control(http_client, device_id, &bearer, body).await?;

    logout(http_client).await
}
