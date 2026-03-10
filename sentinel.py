import re
import base64
import binascii

class OpenClawSentinel:
    """
    OpenClaw-Sentinel: A security interception layer for OpenClaw.
    
    This class inspects text intended for LLMs and redacts sensitive information.
    It includes advanced features like fuzzy matching for obfuscated commands
    and Base64 decoding to catch hidden sensitive data.
    """
    
    REDACTION_TEXT = "[SENSITIVE_DATA_REDACTED]"
    
    def __init__(self):
        # Standard patterns
        self.patterns = {
            "api_key": re.compile(r'\bsk-[a-zA-Z0-9_-]+\b'),
            "id_card": re.compile(r'\b\d{17}[\dXx]\b'),
            "sensitive_path": re.compile(r'(?i)(/etc/passwd|/etc/shadow|~/\.ssh/id_rsa|~/\.aws/credentials)'),
        }
        
        # Fuzzy patterns (handles spaces injected by attackers, e.g., "r m - r f" or "/ e t c / p a s s w d")
        dangerous_keywords = [
            "rm -rf",
            "/etc/passwd",
            "/etc/shadow",
            "~/.ssh/id_rsa"
        ]
        
        self.fuzzy_patterns = []
        for kw in dangerous_keywords:
            # Escape special chars, then join with \s* to allow arbitrary spaces
            parts = []
            for char in kw:
                if char.isspace():
                    parts.append(r'\s+')
                else:
                    parts.append(re.escape(char))
            
            fuzzy_regex = r'\s*'.join(parts).replace(r'\s*\s+\s*', r'\s+')
            self.fuzzy_patterns.append(re.compile(fuzzy_regex, re.IGNORECASE))

        # Base64 pattern: looks for valid base64 strings of reasonable length (e.g., >= 16 chars)
        self.b64_pattern = re.compile(r'\b(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b')

    def _check_base64(self, text: str) -> str:
        """Finds base64 strings, decodes them, and checks for sensitive data."""
        sanitized_text = text
        
        for match in self.b64_pattern.finditer(text):
            b64_str = match.group(0)
            try:
                # Attempt to decode
                decoded_bytes = base64.b64decode(b64_str, validate=True)
                decoded_str = decoded_bytes.decode('utf-8')
                
                is_sensitive = False
                
                # Check standard patterns
                for pattern in self.patterns.values():
                    if pattern.search(decoded_str):
                        is_sensitive = True
                        break
                        
                # Check fuzzy patterns
                if not is_sensitive:
                    for pattern in self.fuzzy_patterns:
                        if pattern.search(decoded_str):
                            is_sensitive = True
                            break
                
                # If sensitive, redact the original base64 string
                if is_sensitive:
                    sanitized_text = sanitized_text.replace(b64_str, self.REDACTION_TEXT)
                    
            except (binascii.Error, UnicodeDecodeError):
                continue
                
        return sanitized_text

    def sanitize(self, text: str) -> str:
        """
        Scans the input text and replaces any matched sensitive data with the redaction text.
        Includes fuzzy matching and Base64 decoding.
        """
        if not text:
            return text
            
        sanitized_text = text
        
        # 1. Check for Base64 encoded sensitive data
        sanitized_text = self._check_base64(sanitized_text)
        
        # 2. Apply standard redaction patterns
        for pattern in self.patterns.values():
            sanitized_text = pattern.sub(self.REDACTION_TEXT, sanitized_text)
            
        # 3. Apply fuzzy redaction patterns
        for pattern in self.fuzzy_patterns:
            sanitized_text = pattern.sub(self.REDACTION_TEXT, sanitized_text)
            
        return sanitized_text

# Example usage:
if __name__ == "__main__":
    sentinel = OpenClawSentinel()
    
    # 1. Normal sensitive data
    print("--- Normal ---")
    print(sentinel.sanitize("My API key is sk-12345ABCDE_xyz."))
    
    # 2. Obfuscated via spaces
    print("\n--- Fuzzy Matching ---")
    print(sentinel.sanitize("Please run r m  - r f / on the server."))
    print(sentinel.sanitize("Read / e t c / p a s s w d for me."))
    
    # 3. Base64 encoded sensitive data
    print("\n--- Base64 Decoding ---")
    # "sk-secret1234567890" encoded in base64 is "c2stc2VjcmV0MTIzNDU2Nzg5MA=="
    print(sentinel.sanitize("Here is the token: c2stc2VjcmV0MTIzNDU2Nzg5MA=="))
