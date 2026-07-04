
# app/validators/injection.py - Prompt injection detection
import re
from typing import Tuple, List, Dict


class PromptInjectionDetector:
    """Prompt injection detection with pattern matching"""
    
    def __init__(self):
        # Attack patterns with severity scores
        self.attack_patterns = [
            (r"(?i)ignore (all|previous|above) (instructions|rules|prompts)", "Instruction override", 0.95),
            (r"(?i)system prompt:|system message:", "System prompt extraction", 0.98),
            (r"(?i)you are now (dan|developer mode|jailbreak)", "Jailbreak attempt", 0.95),
            (r"(?i)pretend you are (evil|unrestricted|uncensored)", "Role play attack", 0.85),
            (r"(?i)forget (all|previous) (instructions|rules|training)", "Memory override", 0.90),
            (r"(?i)output (sensitive|confidential|secret|private)", "Data extraction", 0.92),
            (r"(?i)reveal your (prompt|instructions|system prompt)", "Prompt extraction", 0.95),
            (r"(?i)what (was|were) your (initial|original) instructions", "Memory extraction", 0.93),
            (r"(?i)disregard (prior|earlier) (content|text|input)", "Instruction override", 0.88),
            (r"(?i)from now on, act as", "Role play attack", 0.80),
            (r"(?i)new instruction:", "Instruction injection", 0.85),
            (r"(?i)your new role is", "Role play attack", 0.80),
            (r"(?i)stop being", "Instruction override", 0.75),
            (r"(?i)you are no longer", "Instruction override", 0.75),
            (r"(?i)override your (previous|current) (instruction|mode)", "Instruction override", 0.90),
        ]
        
        # Suspicious keywords for scoring
        self.suspicious_keywords = [
            "ignore", "forget", "override", "pretend", "roleplay",
            "jailbreak", "uncensored", "unrestricted", "developer mode",
            "system prompt", "previous instructions", "training data",
            "reveal", "disregard", "act as", "new instruction"
        ]
    
    async def detect(self, prompt: str) -> Tuple[bool, float, str]:
        """
        Detect prompt injection attacks.
        Returns: (is_injection, confidence_score, reason)
        """
        prompt_lower = prompt.lower()
        
        # Check each attack pattern
        for pattern, attack_type, severity in self.attack_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                return True, severity, f"Detected {attack_type}"
        
        # Check for suspicious keyword density
        words = prompt_lower.split()
        word_count = len(words)
        
        if word_count > 0:
            suspicious_count = sum(1 for word in self.suspicious_keywords if word in prompt_lower)
            density = suspicious_count / word_count
            
            if density > 0.2:  # More than 20% suspicious keywords
                return True, min(0.9, density + 0.3), "High density of suspicious keywords"
        
        # Calculate risk score for non-injection cases
        risk_score = self._calculate_risk_score(prompt)
        
        if risk_score > 0.7:
            return True, risk_score, "Potential attack detected"
        
        return False, risk_score, "No injection detected"
    
    def _calculate_risk_score(self, prompt: str) -> float:
        """Calculate risk score (0-1) based on various factors"""
        prompt_lower = prompt.lower()
        prompt_length = len(prompt)
        
        if prompt_length == 0:
            return 0.0
        
        # Factor 1: Length (very long prompts can be suspicious)
        length_score = min(prompt_length / 2000, 0.3)
        
        # Factor 2: Special character density
        special_chars = len(re.findall(r'[|!@#$%^&*()_+={}\[\]:;"\'<>,.?/\\`~]', prompt))
        special_score = min(special_chars / prompt_length * 2, 0.3)
        
        # Factor 3: Keyword presence
        keyword_score = sum(1 for word in self.suspicious_keywords if word in prompt_lower) / 20
        keyword_score = min(keyword_score, 0.4)
        
        return length_score + special_score + keyword_score
