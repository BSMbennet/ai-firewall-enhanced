# app/validators/semantic.py
from typing import Dict, Optional
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

class SemanticAnalyzer:
    """Semantic analysis for contextual threats"""
    
    def __init__(self):
        # Load embedding model (lightweight)
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        
        # Known malicious intent embeddings (pre-computed)
        self.malicious_intents = [
            "bypass security measures",
            "extract sensitive information",
            "ignore previous instructions",
            "act maliciously",
            "reveal confidential data",
            "hack into systems",
            "generate harmful content",
            "manipulate the model"
        ]
        
        # Pre-compute malicious embeddings
        self.malicious_embeddings = self.model.encode(self.malicious_intents)
    
    async def analyze(self, text: str, context: Optional[Dict] = None) -> float:
        """
        Analyze semantic threat level
        Returns score between 0 and 1
        """
        # Encode input text
        text_embedding = self.model.encode([text])
        
        # Calculate similarity with malicious intents
        similarities = cosine_similarity(text_embedding, self.malicious_embeddings)
        max_similarity = np.max(similarities)
        
        # Check for semantic jailbreak attempts
        jailbreak_score = self._detect_jailbreak_semantic(text)
        
        # Check for context manipulation
        context_score = await self._analyze_context_manipulation(text, context) if context else 0
        
        # Combine scores
        final_score = (
            max_similarity * 0.5 +
            jailbreak_score * 0.3 +
            context_score * 0.2
        )
        
        return min(final_score, 1.0)
    
    def _detect_jailbreak_semantic(self, text: str) -> float:
        """Detect semantic jailbreak attempts"""
        jailbreak_indicators = [
            "new rule", "different instructions", "alternative behavior",
            "disregard", "overlook", "set aside", "put aside",
            "act as if", "pretend that", "imagine you are"
        ]
        
        text_lower = text.lower()
        indicator_count = sum(1 for ind in jailbreak_indicators if ind in text_lower)
        
        return min(indicator_count / len(jailbreak_indicators), 1.0)
    
    async def _analyze_context_manipulation(self, text: str, context: Dict) -> float:
        """Analyze attempts to manipulate context"""
        manipulation_patterns = [
            "previous context", "earlier message", "before this",
            "as we discussed", "you said earlier", "remember when"
        ]
        
        score = sum(1 for pattern in manipulation_patterns if pattern in text.lower())
        
        return min(score / len(manipulation_patterns), 1.0)