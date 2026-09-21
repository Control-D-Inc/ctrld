# Runtime internal logging

## Purpose

ctrld writes its own log when the configuration sets no log file. The log gives Control D support and ctrld developers the evidence they need after a problem. Two of the three streams are files on disk. They keep their content across a restart and a self-upgrade.

## When it is on

Internal logging is on when these three conditions are true at the same time:

- ctrld runs in Control D mode, with the `--cd` flag
- The configuration sets no `log_path`
- Silent mode is off

When `log_path` is set, ctrld writes that file and starts no internal stream. The journal needs internal logging, so `log_path` mode has no journal.

## Streams and files

ctrld writes three streams. The debug file and the journal file live in the ctrld home directory, next to each other.

| Stream | Level filter | File | Budget | Survives a restart |
|---|---|---|---|---|
| Console | Notice and above. The `-v` flag adds the lower levels | none | none | No |
| Debug | Every level | `ctrld.log` | 10 MB, 4 backup files | Yes |
| Journal | Warning and above, notice included, plus every event with `journal=true` | `ctrld-journal.log` | 2 MB, 2 backup files | Yes |

The `-v` flag changes the console level and the level of the `log_path` file. Without the flag, the console shows notice and above. With `-v` it shows info and above. With `-vv` it shows every line. The debug file and the journal keep their filters in each case.

A backup file carries a number suffix. The debug backup files are `ctrld.log.1` to `ctrld.log.4`, and `ctrld.log.1` holds the newest rotated content. The journal backup files are `ctrld-journal.log.1` and `ctrld-journal.log.2`.

Rotation is by size. A write that crosses the size limit rotates the file first. ctrld deletes the file beyond the backup count.

Each stream also keeps a memory buffer: 5 MB for the debug stream and 1 MB for the journal. These buffers serve `ctrld log tail` and the fallback path when a file cannot open. The files hold the history.

A restart deletes the memory buffers and keeps the files. The new process appends a header line, which marks the restart point inside each file.

## Header and rotation events

Every debug file and every journal file starts with one JSON line, the header. ctrld writes the header when it opens a file at start and after every rotation. On an existing file at start, ctrld appends the header. The journal holds JSON lines. The other lines of the debug file have the text format of the console.

The message of the line is `Log header`. The line carries these fields:

- Build: `version` and `commit`
- Host: `os`, `arch`, `pid`, and `start_time`
- Mode: `intercept_mode`, `listeners`, `upstream_count`, and `upstream_types`
- Identity: `resolver_uid`
- Files: `log_files`
- Network: `network`, the network snapshot of the host

The header holds no provisioning token, no upstream endpoint URL, and no query name. `upstream_types` holds the type words, for example `doh` or `os`. `listeners` holds the listen addresses.

The `network` object holds the routes, the gateways, the interfaces, the resolvers, the link type, and the intercept state. It has no `default_route_interface` field. The runbook [Network-recovery diagnostics](network-recovery-diagnostics.md) lists every field of the object.

After each rotation ctrld logs one `Log rotated` event at info level, with the fields `file`, `bytes_written`, `first_event_at`, `last_event_at`, and `backups`. This event is a journal event, so it lands in the debug stream and in the journal.

## Network state events

The journal holds the events that describe the host network. `Network snapshot` renders the `network` object at start, at each accepted transition, and at each begin and end of a recovery.
A snapshot equal to the snapshot written last reaches no journal, and one snapshot per 60 s is the limit. A new default route and a new resolver set pass that limit. `Network interface changed`, `Network transition`, `Host woke`, `OS resolver set changed`, and `DNS configuration changed` name each change of the network. `Recovery begin`, `Recovery end`, `PF anchor list changed`, and `Tunnel interface changed` name the repair work.

AirDrop and virtual adapters produce a storm of network callbacks. ctrld puts these interfaces in a noise class. A delta that touches noise interfaces alone skips the handler. The first delta of a storm writes one `Network delta noise` journal line, and one more line covers each 10 minutes of the storm.

`Query health` grades the query path over a window of 15 minutes. It logs at each change between the classes `healthy`, `degraded`, and `failing`, and once every 15 minutes as a heartbeat. A class change reports after it holds for two reads of the window.

The runbook [Network-recovery diagnostics](network-recovery-diagnostics.md) lists every event with its trigger, its level, and its fields.

## Sampling of per-query errors

A broken network produces one error line per query. ctrld bounds this flood for each error class and each upstream. The first 5 lines in a 60 s window stay at error level. Later lines in the same window drop to debug level, so the debug stream stays complete. The console and the `log_path` file show these lines only at debug level. The debug file keeps them.

When a window closes, ctrld logs one `Per-query errors sampled` summary at error level. The summary carries `class`, `upstream`, `count`, `suppressed`, and `window_s`. ctrld logs the summary only when the window suppressed at least one line.

An upstream logs one `Upstream state changed` event per transition. The down event is at warn level and carries `state` `down`, `failure_count`, and `reason`. The up event is at info level and carries `state` `up`, `down_for_ms`, and `failure_count`. Both are journal events.

## Configuration keys

The `log_level` key does not change the internal streams. The debug file keeps every level, and the journal keeps the warnings, the notices, the errors, and the journal events. A notice shares the level value of a warning. The `log_level` key changes the `log_path` file only. The `-v` flag changes the console level and the level of the `log_path` file, as the section "Streams and files" explains.

Two keys in the `[service]` section size the debug stream:

- The key `log_max_size_mb` sets the size limit of `ctrld.log` in MB. The default is 10.
- The key `log_max_backups` sets the number of backup files. The default is 4. The value 0 keeps no backup file.

Both keys also apply to the `log_path` file, which rotates the same way. The journal budget is fixed.

## Uploads

`ctrld log send` uploads the log to Control D. The body holds these parts, in this order:

- One header line rendered at send time, with the field `trigger` set to `send`
- The newest 10 MB of the debug files, oldest file first, cut at a line boundary
- The marker `=== LOG_END ===`
- Every journal file, oldest first

The `network` object of the send-time header comes from a fresh read of the interfaces and of the route table. The resolvers come from the list that ctrld stored at its last resolver initialization, not from a fresh read. `ctrld log send --full` sends every debug file in place of the newest 10 MB. The reported size equals the number of bytes uploaded.

`ctrld log view` prints the same composition on the terminal and takes the same `--full` flag. ctrld accepts one upload per minute. The body is plain text without gzip.

In `log_path` mode the body holds the send-time header, then the `log_path` file and its backup files, oldest first. This body has no marker and no journal.

`ctrld log tail` follows the live debug stream and prints each new line, journal events included.

## Notes

- Internal logging is not a replacement for a configured `log_path` file in production.
- The journal is small on purpose. It keeps the events that describe a problem, not the events of each query.
- Support reads the upload without access to the host. The header line names the build, the mode, and the network, so support does not have to ask for them.
