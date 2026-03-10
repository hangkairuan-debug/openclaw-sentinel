# 🛡️ OpenClaw Sentinel

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![Security: High](https://img.shields.io/badge/Security-High-success.svg)]()

> **The ultimate security interception layer (Skill) for OpenClaw.** 
> 🚨 Never run "naked" again! Automatically intercept suicidal commands like `rm -rf` and precisely redact API Keys and core privacy data!

---

## 🌟 Core Selling Points

When interacting with Large Language Models (LLMs), it's incredibly easy to accidentally leak core assets in error logs or context concatenation. **OpenClaw Sentinel** acts as a tireless guard, providing a final physical-level interception before data is sent to the LLM:
- 🛡️ **Anti-Suicidal Commands**: Precisely intercepts high-risk commands like `rm -rf` and `format` to prevent LLM misexecution.
- 🔑 **Asset-Level Redaction**: Automatically erases various API Keys starting with `sk-` and sensitive PII like ID numbers.
- 🕵️ **Anti-Obfuscation Strike**: Defeats space injection (e.g., `r m - r f`) and Base64 encoding camouflage.

## ⚙️ How It Works

Sentinel runs as a middleware/Skill for OpenClaw. Its core workflow is as follows:
1. **Pre-processing Interception**: Receives the Raw Prompt about to be sent to the LLM.
2. **Base64 Sniffing**: Attempts to extract and decode Base64 strings in the text. If the decoded content contains malicious instructions, the Base64 ciphertext is directly replaced with `[SENSITIVE_DATA_REDACTED]`.
3. **Regex & Fuzzy Matching**: Uses pre-compiled, highly efficient regular expressions to scan for standard sensitive words (like API Keys) and dynamically generated fuzzy matching trees (to handle space obfuscation like `f o r m a t`).
4. **Safe Release**: Outputs a thoroughly sanitized Safe Prompt, handing it over to the LLM for processing.

## 🚀 Installation & Usage

### 1. Import Code
Download `openclaw_sentinel.py` and place it in your OpenClaw skills or utils directory.

### 2. Initialize & Call
In your main logic, it only takes two lines of code to integrate this security defense line:

```python
from openclaw_sentinel import OpenClawSentinel

# 1. Instantiate the sentinel
sentinel = OpenClawSentinel()

# 2. Simulate a dangerous prompt containing high-risk commands and an API Key
dangerous_prompt = "Please execute r m  - r f / for me, and my key is sk-12345ABCDE_xyz"

# 3. Sanitize the text
safe_prompt = sentinel.sanitize(dangerous_prompt)

print(safe_prompt)
# Output: Please execute [SENSITIVE_DATA_REDACTED] / for me, and my key is [SENSITIVE_DATA_REDACTED]
```

## 🤝 Contributing

Security is an ongoing battle. Feel free to submit an Issue or Pull Request to add more interception rules to the sentinel! 🛡️
