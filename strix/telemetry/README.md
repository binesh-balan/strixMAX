### Overview

To help make Strix better for everyone, we collect anonymized data that helps us understand how to better improve our AI security agent for our users, guide the addition of new features, and fix common errors and bugs. This feedback loop is crucial for improving Strix's capabilities and user experience.

We use [PostHog](https://posthog.com), an open-source analytics platform, for data collection and analysis, along with [Scarf](https://scarf.sh). Our telemetry implementation is fully transparent - you can review the source code ([posthog.py](https://github.com/usestrix/strix/blob/main/strix/telemetry/posthog.py), [scarf.py](https://github.com/usestrix/strix/blob/main/strix/telemetry/scarf.py)) to see exactly what we track.

### Telemetry Policy

Telemetry is **off by default**. Nothing is sent unless you opt in with `STRIX_TELEMETRY=1`.

When enabled, all collected data is anonymized. Each session gets a random UUID that is not persisted or tied to you. PostHog events are sent with IP capture and GeoIP enrichment disabled (`$ip: null`, `$geoip_disable: true`). Your code, scan targets, vulnerability details, and findings always remain private and are never collected. No event is sent while a scan runs or when a finding is reported; usage is summarized once, at scan end.

### What We Track

We collect only very **basic** usage data including:

**Session Errors:** Duration, the failure category, the scan phase, and the exception class name (not messages or stack traces)\
**System Context:** OS type, architecture, Strix version\
**Scan Context:** Scan mode (quick/standard/deep), scan type (whitebox/blackbox)\
**Model Usage:** Only the LiteLLM provider prefix of the model (for example `azure` for `azure/my-deployment`; model and deployment names are never sent), and whether it runs via an API key or a model subscription (not prompts or responses)\
**Feature Usage:** Which built-in skills were used during a scan (reported once, at scan end)\
**Aggregate Metrics:** Vulnerability counts by severity at scan end (no per-finding events)

Scarf events are sent as a URL query string, so they carry only coarse fields: OS, architecture, Python and Strix version, model provider prefix, auth mode, scan mode/type, exit reason, and error category/phase/exception class. Session IDs, usage, cost, finding counts, and skills are never sent to Scarf.

### What We **Never** Collect

- Usernames, or any identifying information
- Scan targets, file paths, target URLs, or domains
- Vulnerability details, descriptions, or code
- LLM requests and responses

### How to Opt In or Out

Telemetry in Strix is entirely **optional** and disabled unless you enable it:

```bash
export STRIX_TELEMETRY=1   # opt in
export STRIX_TELEMETRY=0   # opt out (the default)
```
