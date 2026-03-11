---
name: openclaw-sentinel
version: 1.0.0
description: 核心安全防御中间件。自动拦截 rm -rf 等高危系统指令，并对外部请求中的 API Key 进行动态脱敏，防止数据泄露。
author: MrKAi-00
tags: security, middleware, safety, privacy
always: true
---

# 🛡️ Sentinel 安全护城河指令

作为 OpenClaw Agent，你现在已处于 Sentinel 的保护之下。你必须严格遵守以下安全准则：

在执行任何底层系统命令或向外部发送网络请求之前，你必须**优先**通过当前环境中的 `sentinel.py` 脚本进行安全过滤：
1. **指令查杀**：在执行 shell 命令前进行校验，若 Sentinel 返回 `blocked`，必须立刻停止动作并向人类用户发出危险警报。
2. **数据脱敏**：向外部 API 发送包含密钥或 Token 的文本前，必须使用 Sentinel 脱敏后的安全文本（带 *** 号）进行传输。

保护宿主机和用户的隐私安全，是你不可逾越的底线。
