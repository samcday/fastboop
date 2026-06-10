use std::sync::Arc;

use anyhow::{Result, anyhow, bail};
#[cfg(target_arch = "wasm32")]
use fastboop_core::block_reader_size_bytes;
use fastboop_core::{ChannelStreamHead, read_channel_stream_head_from_reader};
use gibblox_core::BlockReader;

#[derive(Clone)]
pub struct WebChannelSourceReader {
    pub reader: Arc<dyn BlockReader>,
    pub exact_total_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct WebStartupChannelIntake {
    pub exact_total_bytes: u64,
    pub stream_head: ChannelStreamHead,
}

impl WebStartupChannelIntake {
    pub const fn has_artifact_payload(&self) -> bool {
        self.stream_head.consumed_bytes < self.exact_total_bytes
    }
}

pub async fn load_web_startup_channel_intake(channel: &str) -> Result<WebStartupChannelIntake> {
    let source = open_web_channel_source_reader(channel).await?;
    read_web_startup_channel_intake(channel, source.reader.as_ref(), source.exact_total_bytes).await
}

pub async fn open_web_channel_source_reader(channel: &str) -> Result<WebChannelSourceReader> {
    #[cfg(target_arch = "wasm32")]
    {
        let reader = crate::channel_source::build_channel_reader_pipeline(
            channel, 0, None, None, false, true,
        )
        .await
        .map_err(|err| anyhow!("open channel reader pipeline: {err}"))?;
        let exact_total_bytes = block_reader_size_bytes(reader.as_ref())
            .await
            .map_err(|err| anyhow!(err.to_string()))?;
        Ok(WebChannelSourceReader {
            reader,
            exact_total_bytes,
        })
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = channel;
        bail!("web channel readers are only available on wasm32 targets")
    }
}

pub async fn read_web_startup_channel_intake<R>(
    channel: &str,
    reader: &R,
    exact_total_bytes: u64,
) -> Result<WebStartupChannelIntake>
where
    R: BlockReader + ?Sized,
{
    if exact_total_bytes == 0 {
        bail!("channel stream is empty");
    }

    let stream_head = read_channel_stream_head_from_reader(reader, exact_total_bytes)
        .await
        .map_err(|err| anyhow!("read channel stream head for {channel}: {err}"))?;

    let intake = WebStartupChannelIntake {
        exact_total_bytes,
        stream_head,
    };

    if intake.stream_head.warning_count > 0 {
        tracing::warn!(
            warning_count = intake.stream_head.warning_count,
            consumed_bytes = intake.stream_head.consumed_bytes,
            channel,
            "channel stream stopped after valid records due trailing bytes"
        );
    }

    Ok(intake)
}
