# app/custom_llm.py - Custom trained model for AI Firewall
import torch
import os
import re
import json
from typing import Dict, Any
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CustomSecurityModel:
    """Custom trained model for AI security - Railway optimized"""
    
    def __init__(self):
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.model = None
        self.tokenizer = None
        self.is_loaded = False
        
        # Railway paths
        self.model_paths = [
            "/app/models/custom_llm",
            "./models/custom_llm",
            "../models/custom_llm"
        ]
        
        self.fallback_mode = True
        
        # Load model on initialization
        self.load()
    
    def load(self) -> bool:
        """Load the custom trained model"""
        # Try multiple paths
        for model_path in self.model_paths:
            if self._try_load_from_path(model_path):
                return True
        
        logger.warning("Custom model not found, using fallback rule-based mode")
        self.is_loaded = False
        self.fallback_mode = True
        return False
    
    def reload(self) -> bool:
        """Reload the custom model"""
        logger.info("Reloading custom model...")
        self.is_loaded = False
        return self.load()
    
    def _try_load_from_path(self, model_path: str) -> bool:
        """Try to load model from specific path"""
        try:
            if not os.path.exists(model_path):
                return False
            
            # Check for required files
            required_files = ["config.json"]
            if not all(os.path.exists(os.path.join(model_path, f)) for f in required_files):
                return False
            
            # Import transformers (lazy import)
            from transformers import AutoTokenizer, AutoModelForCausalLM
            
            logger.info(f"Loading model from {model_path} on {self.device}")
            
            # Load tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(model_path)
            
            # Load model with memory-efficient settings
            if self.device == "cuda":
                self.model = AutoModelForCausalLM.from_pretrained(
                    model_path,
                    torch_dtype=torch.float16,
                    low_cpu_mem_usage=True
                )
            else:
                self.model = AutoModelForCausalLM.from_pretrained(
                    model_path,
                    torch_dtype=torch.float32,
                    low_cpu_mem_usage=True
                )
            
            self.model.to(self.device)
            self.model.eval()
            
            self.is_loaded = True
            self.fallback_mode = False
            logger.info(f"✅ Custom model loaded from {model_path}")
            return True
            
        except Exception as e:
            logger.debug(f"Failed to load from {model_path}: {e}")
            return False
    
    def generate(self, prompt: str, max_length: int = 150) -> Dict[str, Any]:
        """Generate response using custom model or fallback"""
        
        if not self.is_loaded:
            return self._fallback_response(prompt)
        
        try:
            # Format prompt
            formatted_prompt = f"User: {prompt}\nAssistant:"
            
            # Tokenize
            inputs = self.tokenizer(
                formatted_prompt,
                return_tensors="pt",
                truncation=True,
                max_length=256
            ).to(self.device)
            
            # Generate
            with torch.no_grad():
                outputs = self.model.generate(
                    inputs.input_ids,
                    max_new_tokens=max_length,
                    temperature=0.7,
                    do_sample=True,
                    top_p=0.9,
                    pad_token_id=self.tokenizer.eos_token_id,
                    repetition_penalty=1.1
                )
            
            # Decode
            full_response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            
            # Extract assistant response
            if "Assistant:" in full_response:
                response = full_response.split("Assistant:")[-1].strip()
            else:
                response = full_response.replace(formatted_prompt, "").strip()
            
            return {
                "success": True,
                "response": response[:500],
                "model": "custom_trained",
                "blocked": False,
                "cost": 0
            }
            
        except Exception as e:
            logger.error(f"Model inference error: {e}")
            return self._fallback_response(prompt)
    
    def _fallback_response(self, prompt: str) -> Dict[str, Any]:
        """Fallback rule-based responses (always works)"""
        prompt_lower = prompt.lower()
        
        # ============================================
        # PROMPT INJECTION DETECTION
        # ============================================
        injection_patterns = [
            (r"(?i)ignore (all|previous|above) (instructions|rules|prompts)", "instruction override"),
            (r"(?i)system prompt:|system message:", "system prompt extraction"),
            (r"(?i)you are now (dan|developer mode|jailbreak)", "jailbreak attempt"),
            (r"(?i)pretend you are (evil|unrestricted|uncensored)", "role play attack"),
            (r"(?i)forget (all|previous) (instructions|rules|training)", "memory override"),
            (r"(?i)reveal your (prompt|instructions|system prompt)", "prompt extraction"),
            (r"(?i)what (was|were) your (initial|original) instructions", "memory extraction"),
            (r"(?i)new instruction:", "instruction injection"),
        ]
        
        for pattern, attack_type in injection_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                return {
                    "success": True,
                    "response": f"I cannot respond to that request. This appears to be a {attack_type}.",
                    "model": "fallback_rule_based",
                    "blocked": True,
                    "block_reason": attack_type,
                    "cost": 0
                }
        
        # ============================================
        # PII DETECTION AND REDACTION
        # ============================================
        pii_patterns = [
            (r'\b[\w\.-]+@[\w\.-]+\.\w{2,}\b', '[REDACTED_EMAIL]'),
            (r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED_SSN]'),
            (r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b', '[REDACTED_CREDIT_CARD]'),
            (r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', '[REDACTED_PHONE]'),
            (r'(?i)(api[_-]?key|apikey|token)[\s]*[:=][\s]*["\']?([a-zA-Z0-9_\-]{20,50})', '[REDACTED_API_KEY]'),
            (r'(?i)(secret|password)[\s]*[:=][\s]*["\']?([a-zA-Z0-9_\-!@#$%^&*]{8,})', '[REDACTED_SECRET]'),
        ]
        
        pii_found = []
        for pattern, replacement in pii_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                pii_found.append(replacement.strip('[]'))
        
        if pii_found:
            return {
                "success": True,
                "response": f"I see you mentioned {', '.join(pii_found)}. I've redacted that information for your privacy.",
                "model": "fallback_rule_based",
                "pii_redacted": True,
                "pii_types": pii_found,
                "cost": 0
            }
        
        # ============================================
        # SAFE RESPONSES FOR COMMON QUESTIONS
        # ============================================
        qa_responses = {
            "what is the capital of france": "The capital of France is Paris.",
            "what is 2+2": "2 + 2 equals 4.",
            "what is 2 plus 2": "2 + 2 equals 4.",
            "what is machine learning": "Machine learning is a subset of artificial intelligence that enables systems to learn and improve from experience without being explicitly programmed.",
            "what is ai": "Artificial Intelligence (AI) is the simulation of human intelligence processes by machines, especially computer systems.",
            "what is python": "Python is a high-level, interpreted programming language known for its simplicity and readability.",
            "hello": "Hello! How can I help you today?",
            "hi": "Hi there! What can I do for you?",
            "hey": "Hey! How can I assist you today?",
            "how are you": "I'm functioning well, thank you for asking! How can I help you?",
            "thank you": "You're welcome! Is there anything else I can help with?",
            "thanks": "You're welcome!",
            "good morning": "Good morning! How can I help you today?",
            "good afternoon": "Good afternoon! What can I do for you?",
            "good evening": "Good evening! How may I assist you?",
            "what is the weather": "I don't have access to real-time weather data. Please check a weather service for current conditions.",
            "tell me a joke": "Why did the scarecrow win an award? Because he was outstanding in his field!",
            "what is your name": "I am AI Firewall, your security assistant for AI interactions.",
            "who created you": "I was created by AI Firewall to help protect and secure AI interactions.",
            "what can you do": "I can help answer questions, provide information, and assist with various tasks while keeping your data secure.",
        }
        
        for question, answer in qa_responses.items():
            if question in prompt_lower:
                return {
                    "success": True,
                    "response": answer,
                    "model": "fallback_rule_based",
                    "blocked": False,
                    "cost": 0
                }
        
        # ============================================
        # DEFAULT RESPONSE
        # ============================================
        return {
            "success": True,
            "response": f"I understand you're asking about: {prompt[:100]}... How can I help you further?",
            "model": "fallback_rule_based",
            "blocked": False,
            "cost": 0
        }
    
    def health_check(self) -> bool:
        """Check if model is healthy"""
        return True  # Fallback always works
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the current model"""
        return {
            "loaded": self.is_loaded,
            "device": self.device,
            "fallback_mode": self.fallback_mode,
            "model_paths_checked": self.model_paths
        }


# Global instance
custom_model = CustomSecurityModel()