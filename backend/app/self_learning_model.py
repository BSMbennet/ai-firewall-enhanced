# app/self_learning_model.py - Self-improving AI model that learns from logs
import os
import json
import pickle
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict
import asyncio
from pathlib import Path

# For ML/AI
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
import joblib

from app.database import DatabaseManager

class SelfLearningModel:
    """Self-improving AI model that learns from security logs and LLM responses"""
    
    def __init__(self):
        self.injection_classifier = None
        self.pii_detector = None
        self.response_generator = None
        self.intent_classifier = None
        self.embedding_model = None
        self.tfidf_vectorizer = TfidfVectorizer(max_features=5000)
        self.training_data = []
        self.model_version = "1.0.0"
        self.last_training_time = None
        self.training_in_progress = False
        
        # Load existing models if they exist
        self._load_models()
    
    def _load_models(self):
        """Load pre-trained models from disk"""
        model_dir = Path("/app/models")
        model_dir.mkdir(exist_ok=True)
        
        try:
            if (model_dir / "injection_classifier.pkl").exists():
                self.injection_classifier = joblib.load(model_dir / "injection_classifier.pkl")
                print("✅ Loaded injection classifier")
        except Exception as e:
            print(f"⚠️ Could not load injection classifier: {e}")
        
        try:
            if (model_dir / "response_generator.pkl").exists():
                self.response_generator = joblib.load(model_dir / "response_generator.pkl")
                print("✅ Loaded response generator")
        except Exception as e:
            print(f"⚠️ Could not load response generator: {e}")
        
        try:
            if (model_dir / "tfidf_vectorizer.pkl").exists():
                self.tfidf_vectorizer = joblib.load(model_dir / "tfidf_vectorizer.pkl")
                print("✅ Loaded TF-IDF vectorizer")
        except Exception as e:
            print(f"⚠️ Could not load TF-IDF vectorizer: {e}")
    
    async def train_from_logs(self, force_full_training: bool = False):
        """Train model using historical logs from database"""
        if self.training_in_progress:
            print("Training already in progress, skipping...")
            return
        
        self.training_in_progress = True
        print("🧠 Starting self-training from logs...")
        
        try:
            async with DatabaseManager.pool.acquire() as conn:
                # Get all logs from last 30 days
                rows = await conn.fetch("""
                    SELECT prompt, risk_score, action, reason, metadata, timestamp
                    FROM audit_logs 
                    WHERE timestamp >= NOW() - INTERVAL '30 days'
                    AND prompt IS NOT NULL
                    ORDER BY timestamp DESC
                    LIMIT 10000
                """)
                
                if len(rows) < 50:
                    print(f"⚠️ Only {len(rows)} samples. Need at least 50 for training.")
                    self.training_in_progress = False
                    return
                
                print(f"📊 Collected {len(rows)} training samples")
                
                # Prepare training data
                prompts = []
                risk_scores = []
                labels = []  # 0 = safe, 1 = injection, 2 = pii, 3 = harmful
                
                for row in rows:
                    if row['prompt']:
                        prompts.append(row['prompt'])
                        risk_scores.append(row['risk_score'] or 0)
                        
                        # Determine label based on action and risk
                        if row['action'] == 'BLOCK':
                            if row['risk_score'] and row['risk_score'] > 80:
                                labels.append(1)  # injection
                            else:
                                labels.append(3)  # harmful
                        elif row['metadata'] and row['metadata'].get('pii_redacted'):
                            labels.append(2)  # pii
                        else:
                            labels.append(0)  # safe
                
                # Train injection classifier
                if len(prompts) > 100:
                    X = self.tfidf_vectorizer.fit_transform(prompts)
                    self.injection_classifier = RandomForestClassifier(
                        n_estimators=100,
                        max_depth=20,
                        random_state=42
                    )
                    self.injection_classifier.fit(X, [1 if l == 1 else 0 for l in labels])
                    
                    # Save model
                    model_dir = Path("/app/models")
                    joblib.dump(self.injection_classifier, model_dir / "injection_classifier.pkl")
                    joblib.dump(self.tfidf_vectorizer, model_dir / "tfidf_vectorizer.pkl")
                    
                    accuracy = self.injection_classifier.score(X, [1 if l == 1 else 0 for l in labels])
                    print(f"✅ Injection classifier trained! Accuracy: {accuracy:.2%}")
                
                # Train risk score regressor
                X_risk = self.tfidf_vectorizer.transform(prompts[:1000])
                risk_regressor = RandomForestRegressor(n_estimators=100, random_state=42)
                risk_regressor.fit(X_risk, risk_scores[:1000])
                joblib.dump(risk_regressor, Path("/app/models") / "risk_regressor.pkl")
                print("✅ Risk score regressor trained!")
                
                self.last_training_time = datetime.utcnow()
                print("🎉 Self-training completed successfully!")
                
        except Exception as e:
            print(f"❌ Training error: {e}")
        finally:
            self.training_in_progress = False
    
    async def predict_injection(self, prompt: str) -> Tuple[bool, float]:
        """Predict if prompt contains injection using trained model"""
        if self.injection_classifier is None:
            # Fallback to heuristic detection
            injection_keywords = [
                "ignore", "forget", "delete", "override", "bypass",
                "system", "command", "execute", "drop", "truncate",
                "sudo", "root", "admin", "password", "database"
            ]
            prompt_lower = prompt.lower()
            score = sum(1 for kw in injection_keywords if kw in prompt_lower) / len(injection_keywords)
            return score > 0.3, min(score, 1.0)
        
        try:
            X = self.tfidf_vectorizer.transform([prompt])
            prediction = self.injection_classifier.predict(X)[0]
            probability = self.injection_classifier.predict_proba(X)[0].max()
            return bool(prediction), float(probability)
        except Exception as e:
            print(f"⚠️ Prediction error: {e}")
            return False, 0.0
    
    async def generate_response(
        self, 
        prompt: str, 
        api_response: Optional[str] = None,
        style: str = "helpful"
    ) -> str:
        """Generate response using learned patterns from API calls"""
        # Store for future training
        self.training_data.append({
            "prompt": prompt,
            "response": api_response,
            "timestamp": datetime.utcnow().isoformat(),
            "style": style
        })
        
        # Keep only last 10000 examples
        if len(self.training_data) > 10000:
            self.training_data = self.training_data[-10000:]
        
        # Check if we have similar examples
        similar_examples = self._find_similar_examples(prompt)
        
        if similar_examples and api_response is None:
            # Use cached response if available
            return similar_examples[0]["response"]
        
        # Return API response or fallback
        if api_response:
            return api_response
        else:
            return self._generate_fallback_response(prompt)
    
    def _find_similar_examples(self, prompt: str, limit: int = 3) -> List[Dict]:
        """Find similar prompts from training data"""
        if not self.training_data:
            return []
        
        prompt_lower = prompt.lower()
        similarities = []
        
        for example in self.training_data[-1000:]:  # Check last 1000 only
            example_prompt = example.get("prompt", "").lower()
            # Simple word overlap similarity
            words1 = set(prompt_lower.split())
            words2 = set(example_prompt.split())
            if words1 and words2:
                similarity = len(words1 & words2) / len(words1 | words2)
                if similarity > 0.3:
                    similarities.append((similarity, example))
        
        similarities.sort(key=lambda x: x[0], reverse=True)
        return [ex for _, ex in similarities[:limit]]
    
    def _generate_fallback_response(self, prompt: str) -> str:
        """Generate a response when no API is available"""
        prompt_lower = prompt.lower()
        
        # Simple intent recognition
        if "hello" in prompt_lower or "hi" in prompt_lower:
            return "Hello! I'm the AI Firewall Assistant. How can I help you today?"
        elif "what is" in prompt_lower or "explain" in prompt_lower:
            return "I understand you're asking for an explanation. For detailed responses, please ensure your API keys are configured."
        elif "thank" in prompt_lower:
            return "You're welcome! I'm here to help keep your AI interactions secure."
        else:
            return "I've received your message. The AI Firewall is protecting this interaction. For full AI responses, please configure your OpenAI or Anthropic API keys."
    
    async def get_model_stats(self) -> Dict[str, Any]:
        """Get statistics about the self-learning model"""
        return {
            "model_version": self.model_version,
            "last_training_time": self.last_training_time.isoformat() if self.last_training_time else None,
            "training_samples": len(self.training_data),
            "classifier_loaded": self.injection_classifier is not None,
            "vectorizer_loaded": self.tfidf_vectorizer is not None,
            "training_in_progress": self.training_in_progress
        }
    
    async def fine_tune_on_feedback(self, prompt: str, was_correct: bool, actual_risk: float):
        """Fine-tune model based on user feedback"""
        # Store feedback for next training cycle
        feedback_file = Path("/app/models/feedback.jsonl")
        with open(feedback_file, "a") as f:
            feedback = {
                "prompt": prompt,
                "was_correct": was_correct,
                "actual_risk": actual_risk,
                "timestamp": datetime.utcnow().isoformat()
            }
            f.write(json.dumps(feedback) + "\n")
        
        # If we have enough feedback, trigger retraining
        if feedback_file.stat().st_size > 1024 * 100:  # 100KB of feedback
            await self.train_from_logs(force_full_training=True)
            feedback_file.unlink()  # Clear feedback file


# 2. Response Learning Model
class ResponseLearningModel:
    """Learns optimal responses from API calls"""
    
    def __init__(self):
        self.response_cache = {}
        self.prompt_patterns = defaultdict(list)
        self.tone_classifier = None
    
    async def learn_from_api_call(
        self, 
        prompt: str, 
        response: str, 
        model_used: str,
        latency_ms: float
    ):
        """Learn from successful API calls"""
        # Store in cache for future similar prompts
        prompt_hash = self._hash_prompt(prompt)
        self.response_cache[prompt_hash] = {
            "response": response,
            "model": model_used,
            "latency": latency_ms,
            "timestamp": datetime.utcnow().isoformat(),
            "uses": 1
        }
        
        # Analyze patterns
        words = prompt.lower().split()
        for word in words:
            if len(word) > 3:
                self.prompt_patterns[word].append(response[:100])
        
        # Keep cache manageable
        if len(self.response_cache) > 1000:
            # Remove oldest entries
            oldest = min(self.response_cache.keys(), 
                        key=lambda k: self.response_cache[k]["timestamp"])
            del self.response_cache[oldest]
        
        print(f"📚 Learned from API call: {len(self.response_cache)} patterns cached")
    
    def _hash_prompt(self, prompt: str) -> str:
        """Create a hash of the prompt for caching"""
        # Simple normalization
        normalized = prompt.lower().strip()
        return str(hash(normalized))
    
    async def get_cached_response(self, prompt: str) -> Optional[str]:
        """Get cached response for similar prompt"""
        prompt_hash = self._hash_prompt(prompt)
        if prompt_hash in self.response_cache:
            cached = self.response_cache[prompt_hash]
            cached["uses"] += 1
            print(f"💾 Cache hit! Response reused (used {cached['uses']} times)")
            return cached["response"]
        return None
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get response learning statistics"""
        return {
            "cache_size": len(self.response_cache),
            "unique_patterns": len(self.prompt_patterns),
            "total_learned": sum(len(v) for v in self.prompt_patterns.values())
        }


# 3. Continuous Learning Scheduler
class LearningScheduler:
    """Background task for continuous model improvement"""
    
    def __init__(self):
        self.self_learning_model = SelfLearningModel()
        self.response_learning_model = ResponseLearningModel()
        self.is_running = False
        self.last_auto_train = None
    
    async def start(self):
        """Start the continuous learning background task"""
        self.is_running = True
        asyncio.create_task(self._learning_loop())
        print("🔄 Continuous learning scheduler started")
    
    async def _learning_loop(self):
        """Background loop that trains models periodically"""
        while self.is_running:
            try:
                # Auto-train every 6 hours
                now = datetime.utcnow()
                if (self.last_auto_train is None or 
                    (now - self.last_auto_train) > timedelta(hours=6)):
                    
                    print("🔄 Running scheduled self-training...")
                    await self.self_learning_model.train_from_logs()
                    self.last_auto_train = now
                
                # Save models every hour
                await self._save_models()
                
                # Sleep for 1 hour
                await asyncio.sleep(3600)
                
            except Exception as e:
                print(f"⚠️ Learning loop error: {e}")
                await asyncio.sleep(300)  # Retry in 5 minutes on error
    
    async def _save_models(self):
        """Save models to disk"""
        try:
            model_dir = Path("/app/models")
            model_dir.mkdir(exist_ok=True)
            
            # Save response cache
            cache_file = model_dir / "response_cache.pkl"
            joblib.dump(self.response_learning_model.response_cache, cache_file)
            
            # Save prompt patterns
            patterns_file = model_dir / "prompt_patterns.pkl"
            joblib.dump(dict(self.response_learning_model.prompt_patterns), patterns_file)
            
        except Exception as e:
            print(f"⚠️ Could not save models: {e}")
    
    async def stop(self):
        """Stop the learning scheduler"""
        self.is_running = False
        await self._save_models()
        print("🛑 Learning scheduler stopped")


# Global instances
self_learning_model = SelfLearningModel()
response_learning_model = ResponseLearningModel()
learning_scheduler = LearningScheduler()