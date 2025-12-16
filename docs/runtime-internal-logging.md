# Runtime Internal Logging

When no logging is configured (i.e., `log_path` is not set), ctrld automatically enables an internal logging system. This system stores logs in memory to provide troubleshooting information when problems occur.

## Purpose

The runtime internal logging system is designed primarily for **ctrld developers**, not end users. It captures detailed diagnostic information that can be useful for troubleshooting issues when they arise, especially in production environments where explicit logging may not be configured.

## When It's Enabled

Internal logging is automatically enabled when:

- ctrld is running in Control D mode (i.e., `--cd` flag is provided)
- No log file is configured (i.e., `log_path` is empty or not set)

If a log file is explicitly configured via `log_path`, internal logging will **not** be enabled, as the configured log file serves the logging purpose.

## How It Works

The internal logging system:

- Stores logs in **in-memory buffers** (not written to disk)
- Captures logs at **debug level** for normal operations and **warn level** for warnings
- Maintains separate buffers for normal logs and warning logs
- Automatically manages buffer size to prevent unbounded memory growth
- Preserves initialization logs even when buffers overflow

## Configuration

**Important**: The `log_level` configuration option does **not** affect the internal logging system. Internal logging always operates at debug level for normal logs and warn level for warnings, regardless of the `log_level` setting in the configuration file.

The `log_level` setting only affects:
- Console output (when running interactively)
- File-based logging (when `log_path` is configured)

## Accessing Internal Logs

Internal logs can be accessed through the control server API endpoints. This functionality is intended for developers and support personnel who need to diagnose issues.

## Notes

- Internal logging is **not** a replacement for proper log file configuration in production environments
- For production deployments, it is recommended to configure `log_path` to enable persistent file-based logging
- Internal logs are stored in memory and will be lost if the process terminates unexpectedly
- The internal logging system is automatically disabled when explicit logging is configured

