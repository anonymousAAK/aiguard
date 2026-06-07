use std::path::PathBuf;

use anyhow::{Context, Result};
use directories::ProjectDirs;

pub async fn run_pull(model: &str) -> Result<()> {
    let (url, filename) = match model {
        "pi-detector" | "prompt-injection" | "pi-v2" => (
            "https://huggingface.co/ProtectAI/deberta-v3-base-prompt-injection-v2/resolve/main/onnx/model.onnx",
            "pi-v2.onnx",
        ),
        _ => anyhow::bail!("Unknown model: {}. Available: pi-detector, prompt-injection, pi-v2", model),
    };

    let models_dir = models_dir()?;
    std::fs::create_dir_all(&models_dir).with_context(|| {
        format!(
            "Failed to create models directory: {}",
            models_dir.display()
        )
    })?;
    let dest = models_dir.join(filename);

    if dest.exists() {
        println!("Model already downloaded: {}", dest.display());
        println!("Delete it and re-run to force re-download.");
        return Ok(());
    }

    println!("Downloading {} (~440 MB)...", model);
    println!("URL: {}", url);
    println!("Destination: {}", dest.display());

    download_with_progress(url, &dest).await?;

    println!("\nModel downloaded successfully.");
    println!("To enable: set `tier_model = true` in [scanners.prompt_injection] in aiguard.toml");
    Ok(())
}

async fn download_with_progress(url: &str, dest: &PathBuf) -> Result<()> {
    let client = reqwest::Client::builder()
        .build()
        .context("Failed to build HTTP client")?;

    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("Failed to fetch {}", url))?;

    if !response.status().is_success() {
        anyhow::bail!("Download failed with HTTP status: {}", response.status());
    }

    let total_bytes = response.content_length();

    let mut file = tokio::fs::File::create(dest)
        .await
        .with_context(|| format!("Failed to create file: {}", dest.display()))?;

    let mut downloaded: u64 = 0;
    let mut last_reported_mb: u64 = 0;
    let mut stream = response;

    // Read in chunks using bytes() streaming via chunk()
    loop {
        let chunk = stream
            .chunk()
            .await
            .context("Error reading response body")?;
        match chunk {
            None => break,
            Some(bytes) => {
                tokio::io::AsyncWriteExt::write_all(&mut file, &bytes)
                    .await
                    .context("Failed to write to file")?;
                downloaded += bytes.len() as u64;

                let downloaded_mb = downloaded / (10 * 1024 * 1024);
                if downloaded_mb > last_reported_mb {
                    last_reported_mb = downloaded_mb;
                    let downloaded_display = downloaded / (1024 * 1024);
                    match total_bytes {
                        Some(total) => {
                            let total_display = total / (1024 * 1024);
                            println!(
                                "Downloaded {} MB / {} MB",
                                downloaded_display, total_display
                            );
                        }
                        None => {
                            println!("Downloaded {} MB", downloaded_display);
                        }
                    }
                }
            }
        }
    }

    tokio::io::AsyncWriteExt::flush(&mut file)
        .await
        .context("Failed to flush file")?;

    let metadata = tokio::fs::metadata(dest)
        .await
        .with_context(|| format!("Failed to stat downloaded file: {}", dest.display()))?;

    if metadata.len() == 0 {
        anyhow::bail!("Downloaded file is empty: {}", dest.display());
    }

    println!("Model saved to {}", dest.display());
    Ok(())
}

fn models_dir() -> Result<PathBuf> {
    if let Some(proj_dirs) = ProjectDirs::from("", "", "aiguard") {
        Ok(proj_dirs.data_local_dir().join("models"))
    } else {
        // Fallback to ~/.aiguard/models
        let home = dirs_fallback()?;
        Ok(home.join(".aiguard").join("models"))
    }
}

fn dirs_fallback() -> Result<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(PathBuf::from)
        .or_else(|| std::env::var("USERPROFILE").ok().map(PathBuf::from))
        .context("Could not determine home directory")
}
