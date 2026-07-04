# app/validators/pii.py
import re
from typing import List, Tuple, Dict
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
import phonenumbers
from email_validator import validate_email, EmailNotValidError

class PIIDetector:
    """Comprehensive PII detection and redaction"""
    
    def __init__(self):
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
        
        # Custom patterns for sensitive data
        self.custom_patterns = {
            "API_KEY": {
                "pattern": r"(?i)(api[_-]?key|apikey|token|access_token)[\s]*[:=][\s]*['\"]?([a-zA-Z0-9_\-]{20,50})",
                "score": 0.95
            },
            "SECRET_KEY": {
                "pattern": r"(?i)(secret|password|passwd|pwd)[\s]*[:=][\s]*['\"]?([a-zA-Z0-9_\-!@#$%^&*]{10,})",
                "score": 0.98
            },
            "JWT_TOKEN": {
                "pattern": r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
                "score": 0.99
            },
            "AWS_KEY": {
                "pattern": r"AKIA[0-9A-Z]{16}",
                "score": 0.99
            },
            "CREDIT_CARD": {
                "pattern": r"\b(?:\d[ -]*?){13,16}\b",
                "score": 0.90
            },
            "SSN": {
                "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
                "score": 0.95
            },
            "IP_ADDRESS": {
                "pattern": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
                "score": 0.70
            },
            "EMAIL": {
                "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                "score": 0.85
            }
        }
    
    async def detect_and_redact(self, text: str, redact: bool = True) -> Tuple[str, List[Dict]]:
        """Detect PII and optionally redact"""
        detected_pii = []
        
        # Use Presidio for standard PII
        analyzer_results = self.analyzer.analyze(
            text=text,
            entities=["EMAIL", "PHONE_NUMBER", "PERSON", "LOCATION", "SSN", "CREDIT_CARD", "US_DRIVER_LICENSE"],
            language="en"
        )
        
        for result in analyzer_results:
            detected_pii.append({
                "type": result.entity_type,
                "start": result.start,
                "end": result.end,
                "score": result.score,
                "text": text[result.start:result.end]
            })
        
        # Custom pattern detection
        for pattern_name, pattern_info in self.custom_patterns.items():
            matches = re.finditer(pattern_info["pattern"], text, re.IGNORECASE)
            for match in matches:
                detected_pii.append({
                    "type": pattern_name,
                    "start": match.start(),
                    "end": match.end(),
                    "score": pattern_info["score"],
                    "text": match.group(0)
                })
        
        # Remove duplicates (overlapping detections)
        detected_pii = self._deduplicate_detections(detected_pii)
        
        # Redact if requested
        redacted_text = text
        if redact and detected_pii:
            # Sort by start index in reverse to avoid index shifting
            detected_pii.sort(key=lambda x: x["start"], reverse=True)
            
            for pii in detected_pii:
                redacted_text = (
                    redacted_text[:pii["start"]] +
                    f"[REDACTED_{pii['type']}]" +
                    redacted_text[pii["end"]:]
                )
        
        return redacted_text, detected_pii
    
    def _deduplicate_detections(self, detections: List[Dict]) -> List[Dict]:
        """Remove overlapping detections, keeping highest confidence"""
        if not detections:
            return []
        
        # Sort by start position
        detections.sort(key=lambda x: (x["start"], -x["score"]))
        
        unique = []
        for detection in detections:
            if not unique:
                unique.append(detection)
            else:
                last = unique[-1]
                # Check for overlap
                if detection["start"] < last["end"]:
                    # Overlap - keep higher score
                    if detection["score"] > last["score"]:
                        unique[-1] = detection
                else:
                    unique.append(detection)
        
        return unique
    
    def validate_email_format(self, email: str) -> bool:
        """Validate email format"""
        try:
            validate_email(email)
            return True
        except EmailNotValidError:
            return False
    
    def validate_phone(self, phone: str) -> bool:
        """Validate phone number"""
        try:
            parsed = phonenumbers.parse(phone, "US")
            return phonenumbers.is_valid_number(parsed)
        except:
            return False