import re

class SentinelMasker:
    def __init__(self):
        # 建立一个“高危敏感特征”的规则字典
        self.rules = {
            "OpenAI_Key": r"sk-[a-zA-Z0-9]{32,48}",          # 匹配 OpenAI API Key
            "GitHub_Token": r"gh[p|u|s|r]_[a-zA-Z0-9]{36}", # 匹配各类 GitHub Token
            "AWS_Access_Key": r"AKIA[0-9A-Z]{16}",          # 匹配 AWS 访问凭证
            "Bearer_Token": r"Bearer\s+([a-zA-Z0-9\-\._]{30,})" # 匹配常见身份令牌
        }

    def _mask_secret(self, match):
        """
        优雅的遮蔽算法：保留头部前5位和尾部后3位，中间全部打上星号。
        比如：sk-1234567890abcdef -> sk-12***def
        """
        secret = match.group(0)
        
        # 如果长度太短，为了安全直接全部变星号
        if len(secret) <= 10:
            return "*" * len(secret)
            
        head = secret[:5]
        tail = secret[-3:]
        return f"{head}***{tail}"

    def sanitize(self, text):
        """
        核心扫描器：遍历所有规则，扫描并替换文本中的敏感词
        """
        safe_text = text
        for rule_name, pattern in self.rules.items():
            # 使用 re.sub 的高级用法：传入一个函数动态计算替换内容
            safe_text = re.sub(pattern, self._mask_secret, safe_text)
        
        return safe_text

# ==========================================
# 🚀 本地测试跑道 (供你在 Cursor 里测试运行)
# ==========================================
if __name__ == "__main__":
    sentinel = SentinelMasker()
    
    # 模拟一段 OpenClaw 准备发往外部的危险日志
    danger_log = """
    任务执行完毕。
    准备上传文件到 AWS，使用的 Access Key 是 AKIA1234567890ABCDEF。
    另外，刚才调用的 LLM 返回了结果，使用的 Token 是 sk-proj-ab12cd34ef56gh78ij90klmnopqrstuvwxyz。
    """
    
    print("🚨 拦截前的原始文本：")
    print(danger_log)
    
    safe_log = sentinel.sanitize(danger_log)
    
    print("-" * 40)
    print("🛡️ Sentinel 脱敏后的安全文本：")
    print(safe_log)
