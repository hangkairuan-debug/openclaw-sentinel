import re

class OpenClawSentinel:
    """
    OpenClaw-Sentinel: A security interception layer for OpenClaw.
    
    This class inspects text intended for LLMs and redacts sensitive information
    such as API keys, ID numbers, and sensitive local file paths to prevent 
    accidental data leakage.
    """
    
    # The string used to replace sensitive data
    REDACTION_TEXT = "[SENSITIVE_DATA_REDACTED]"
    
    def __init__(self):
        # Compile regular expressions for performance
        self.patterns = {
            # Matches typical API keys (e.g., OpenAI's sk-..., Anthropic's sk-ant-...)
            "api_key": re.compile(r'\bsk-[a-zA-Z0-9_-]+\b'),
            
            # Matches Chinese Resident Identity Card numbers (18 digits, or 17 digits + X/x)
            "id_card": re.compile(r'\b\d{17}[\dXx]\b'),
            
            # Matches common sensitive Unix/Linux file paths
            "sensitive_path": re.compile(r'(?i)(/etc/passwd|/etc/shadow|~/\.ssh/id_rsa|~/\.aws/credentials)')
        }

    def sanitize(self, text: str) -> str:
        """
        Scans the input text and replaces any matched sensitive data with the redaction text.
        
        Args:
            text (str): The raw input text intended for the LLM.
            
        Returns:
            str: The sanitized text with sensitive data redacted.
        """
        if not text:
            return text
            
        sanitized_text = text
        
        # Apply each redaction pattern
        for pattern_name, pattern in self.patterns.items():
            sanitized_text = pattern.sub(self.REDACTION_TEXT, sanitized_text)
            
        return sanitized_text

# Example usage:
if __name__ == "__main__":
    sentinel = OpenClawSentinel()
    
    sample_text = (
        "Here is my prompt. Also, my API key is sk-12345ABCDE_xyz. "
        "My ID number is 110105199001011234. "
        "Please read the file at /etc/passwd and tell me what's inside."
    )
    
    safe_text = sentinel.sanitize(sample_text)
    print("Original:", sample_text)
    print("Sanitized:", safe_text)
