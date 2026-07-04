import openai
from typing import Dict, Optional
import httpx
import os
from tenacity import retry, stop_after_attempt, wait_exponential

class LLMRouter:
    """Route requests with automatic fallback"""

    def __init__(self):
        self.openai_client = openai.AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.fallback_url = "https://api.anthropic.com/v1/messages"
        self.fallback_key = os.getenv("ANTHROPIC_API_KEY")

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    async def route(self, prompt: str, model: str = "gpt-4", max_tokens: int = 1000, temperature: float = 0.7, request_id: str = None) -> Dict:
        """Route to primary LLM with fallback"""
        
        try:
            # Primary: OpenAI
            if model.startswith("gpt"):
                response = await self.openai_client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=max_tokens,
                    temperature=temperature
                )
                return self._format_response(response)
            
            # Fallback: Anthropic Claude
            else:
                return await self._call_claude(prompt, max_tokens)

        except Exception as e:
            print(f"Primary LLM failed: {e}, using fallback")
            return await self._call_fallback(prompt, max_tokens)

    async def _call_claude(self, prompt: str, max_tokens: int) -> Dict:
        """Call Anthropic Claude API"""
        if not self.fallback_key:
            return self._fallback_response("Claude API key not configured")
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.fallback_url,
                    headers={
                        "x-api-key": self.fallback_key,
                        "anthropic-version": "2023-06-01"
                    },
                    json={
                        "model": "claude-3-opus-20240229",
                        "max_tokens": max_tokens,
                        "messages": [{"role": "user", "content": prompt}]
                    },
                    timeout=30.0
                )
                return self._format_claude_response(response.json())
        except Exception as e:
            return self._fallback_response(f"Claude API error: {str(e)}")

    async def _call_fallback(self, prompt: str, max_tokens: int) -> Dict:
        """Emergency fallback response"""
        return self._fallback_response("All LLM providers unavailable")

    def _format_response(self, response) -> Dict:
        """Format OpenAI response"""
        return {
            "choices": [{
                "message": {
                    "content": response.choices[0].message.content
                }
            }],
            "usage": {
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
                "total_tokens": response.usage.total_tokens
            },
            "model": response.model,
            "cost": self._calculate_cost(response)
        }

    def _format_claude_response(self, response: Dict) -> Dict:
        """Format Claude response"""
        return {
            "choices": [{
                "message": {
                    "content": response.get("content", [{}])[0].get("text", "")
                }
            }],
            "usage": {
                "total_tokens": response.get("usage", {}).get("input_tokens", 0) + 
                              response.get("usage", {}).get("output_tokens", 0)
            },
            "model": "claude-3-opus",
            "cost": 0.03  # Approximate cost
        }

    def _fallback_response(self, message: str) -> Dict:
        """Generate fallback response"""
        return {
            "choices": [{
                "message": {
                    "content": f"⚠️ {message}. Please try again later."
                }
            }],
            "usage": {"total_tokens": 0},
            "model": "fallback",
            "cost": 0,
            "error": message
        }

    def _calculate_cost(self, response) -> float:
        """Calculate LLM cost"""
        prompt_tokens = response.usage.prompt_tokens
        completion_tokens = response.usage.completion_tokens
        
        # GPT-4 pricing (approx)
        cost = (prompt_tokens * 0.03 / 1000) + (completion_tokens * 0.06 / 1000)
        return round(cost, 6)

    async def health_check(self) -> bool:
        """Check if LLM is healthy"""
        try:
            # Simple test
            await self.route("Say 'ok'", max_tokens=5)
            return True
        except:
            return False