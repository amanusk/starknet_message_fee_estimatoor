use crate::config::settings::LoggingConfig;
use eyre::Result;
use flexi_logger::{FileSpec, Logger, WriteMode};
use log::LevelFilter;
use std::path::Path;

pub fn init_logging(config: &LoggingConfig) -> Result<()> {
    // Create logs directory if it doesn't exist
    if let Some(log_dir) = Path::new(&config.log_file).parent() {
        std::fs::create_dir_all(log_dir)?;
    }

    // Parse log level
    let level_filter = match config.level.to_lowercase().as_str() {
        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        _ => LevelFilter::Info,
    };

    // Build logger with file rotation
    let mut logger = Logger::try_with_str(level_filter.to_string())?
        .format(flexi_logger::colored_detailed_format)
        .log_to_file(
            FileSpec::default()
                .directory("logs")
                .basename("starknet_fee_estimator"),
        )
        .rotate(
            flexi_logger::Criterion::Size(config.max_file_size_mb * 1024 * 1024),
            flexi_logger::Naming::Timestamps,
            flexi_logger::Cleanup::KeepLogFiles(config.max_files),
        )
        .write_mode(WriteMode::BufferAndFlush);

    // Add console output if enabled
    if config.enable_console {
        logger = logger.duplicate_to_stdout(flexi_logger::Duplicate::from(level_filter));
    }

    // Start the logger
    logger.start()?;

    Ok(())
}
