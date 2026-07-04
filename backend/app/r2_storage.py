import boto3
from botocore.config import Config
import os
from typing import BinaryIO, Optional, Dict, Any
import uuid
import json
from datetime import datetime

class CloudflareR2:
    def __init__(self):
        self.endpoint = os.getenv("CLOUDFLARE_R2_ENDPOINT")
        self.access_key = os.getenv("CLOUDFLARE_R2_ACCESS_KEY")
        self.secret_key = os.getenv("CLOUDFLARE_R2_SECRET_KEY")
        self.bucket = os.getenv("CLOUDFLARE_R2_BUCKET", "ai-firewall")
        self.client = None
        self._initialized = False

    async def initialize(self):
        """Initialize R2 client"""
        try:
            if self.endpoint and self.access_key and self.secret_key:
                self.client = boto3.client(
                    's3',
                    endpoint_url=self.endpoint,
                    aws_access_key_id=self.access_key,
                    aws_secret_access_key=self.secret_key,
                    config=Config(signature_version='s3v4'),
                    region_name='auto'
                )
                # Test connection
                self.client.head_bucket(Bucket=self.bucket)
                self._initialized = True
                print("✅ Cloudflare R2 connected")
            else:
                print("⚠️ R2 credentials not set, using mock storage")
                self._initialized = True
        except Exception as e:
            print(f"⚠️ Failed to connect to R2: {e}")
            self._initialized = True

    async def health_check(self) -> bool:
        """Check if R2 is healthy"""
        try:
            if not self.client:
                return False
            self.client.head_bucket(Bucket=self.bucket)
            return True
        except:
            return False

    async def upload_json(self, data: Dict, path: str = None) -> str:
        """Upload JSON data to R2"""
        if not self.client:
            return None
        
        try:
            if not path:
                filename = f"data/{datetime.utcnow().strftime('%Y/%m/%d')}/{uuid.uuid4()}.json"
            else:
                filename = path
            
            self.client.put_object(
                Bucket=self.bucket,
                Key=filename,
                Body=json.dumps(data).encode('utf-8'),
                ContentType='application/json'
            )
            
            return f"https://{self.bucket}.r2.cloudflarestorage.com/{filename}"
        except Exception as e:
            print(f"Upload error: {e}")
            return None

    async def download_json(self, path: str) -> Optional[Dict]:
        """Download JSON data from R2"""
        if not self.client:
            return None
        
        try:
            response = self.client.get_object(
                Bucket=self.bucket,
                Key=path
            )
            data = json.loads(response['Body'].read().decode('utf-8'))
            return data
        except Exception as e:
            print(f"Download error: {e}")
            return None

    async def upload_file(self, file_data: bytes, filename: str, content_type: str = 'application/octet-stream') -> str:
        """Upload file to R2"""
        if not self.client:
            return None
        
        try:
            key = f"files/{datetime.utcnow().strftime('%Y/%m/%d')}/{filename}"
            
            self.client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=file_data,
                ContentType=content_type
            )
            
            return f"https://{self.bucket}.r2.cloudflarestorage.com/{key}"
        except Exception as e:
            print(f"Upload file error: {e}")
            return None

    async def delete_file(self, path: str) -> bool:
        """Delete file from R2"""
        if not self.client:
            return False
        
        try:
            self.client.delete_object(
                Bucket=self.bucket,
                Key=path
            )
            return True
        except Exception as e:
            print(f"Delete error: {e}")
            return False

    async def list_files(self, prefix: str = "", limit: int = 100) -> list:
        """List files in bucket"""
        if not self.client:
            return []
        
        try:
            response = self.client.list_objects_v2(
                Bucket=self.bucket,
                Prefix=prefix,
                MaxKeys=limit
            )
            
            files = []
            for obj in response.get('Contents', []):
                files.append({
                    'key': obj['Key'],
                    'size': obj['Size'],
                    'last_modified': obj['LastModified'].isoformat()
                })
            
            return files
        except Exception as e:
            print(f"List error: {e}")
            return []

    async def archive_audit_logs(self, older_than_days: int = 30):
        """Archive old audit logs to R2"""
        # This is a placeholder - implement based on your needs
        pass