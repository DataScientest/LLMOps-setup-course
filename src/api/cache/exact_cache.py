"""
Exact Cache Implementation

This module provides exact cache functionality using MD5 hashing for fast lookup
of identical prompts. It's designed to be lightweight and fast, handling only
exact matches (similarity = 1.0).

The cache uses Qdrant as the storage backend but with a simplified approach:
- Uses MD5 hash of the prompt as the cache key
- Stores exact responses with metadata
- No embedding computation needed
"""

import hashlib
import logging
import time
import uuid
from typing import Any, Dict, Optional

from qdrant_client import QdrantClient
from qdrant_client.models import Distance, PointStruct, VectorParams

logger = logging.getLogger(__name__)


class ExactCache:
    """Exact cache implementation using Qdrant for storage"""

    def __init__(
        self,
        qdrant_url: str = "http://localhost:6333",
        ttl_seconds: int = 1800,
        client: Optional[QdrantClient] = None,
    ):
        self.qdrant_client = client or QdrantClient(url=qdrant_url)
        self.ttl = ttl_seconds
        self.collection_name = "exact_cache"
        self._init_collection()

    def _init_collection(self):
        """Initialize Qdrant collection for exact cache"""
        try:
            # Check if collection exists
            collections = self.qdrant_client.get_collections()
            collection_names = [c.name for c in collections.collections]

            if self.collection_name not in collection_names:
                # Create collection with minimal vector size (1) since we don't use embeddings
                self.qdrant_client.create_collection(
                    collection_name=self.collection_name,
                    vectors_config=VectorParams(
                        size=1,  # Minimal size since we don't use embeddings
                        distance=Distance.COSINE,
                    ),
                )
                logger.info(f"Created exact cache collection: {self.collection_name}")
        except Exception as e:
            logger.error(f"Failed to initialize exact cache collection: {e}")
            raise

    def _hash_prompt(self, prompt: str, model: str, **kwargs) -> str:
        """Create MD5 hash of prompt, model and parameters"""
        # Create a consistent hash key
        hash_data = f"{prompt}|{model}"
        for key, value in sorted(kwargs.items()):
            hash_data += f"|{key}:{value}"
        digest = hashlib.md5(hash_data.encode()).hexdigest()
        return str(uuid.UUID(digest))

    def _is_expired(self, timestamp: float) -> bool:
        """Check if cache entry is expired"""
        return time.time() - timestamp > self.ttl

    def get(self, prompt: str, model: str, **kwargs) -> Optional[Dict[str, Any]]:
        """
        Get cached response for exact prompt match
        Returns response dict or None
        """
        try:
            # Create hash key
            cache_key = self._hash_prompt(prompt, model, **kwargs)

            # Try to retrieve from Qdrant
            result = self.qdrant_client.retrieve(
                collection_name=self.collection_name, ids=[cache_key]
            )

            if result:
                payload = result[0].payload

                # Check TTL
                if self._is_expired(payload.get("timestamp", 0)):
                    # Delete expired entry
                    self.qdrant_client.delete(
                        collection_name=self.collection_name,
                        points_selector=[cache_key],
                    )
                    return None

                # Check model compatibility
                if payload.get("model") != model:
                    return None

                logger.info("Exact cache hit")
                return payload.get("response")

            return None

        except Exception as e:
            logger.error(f"Error getting exact cache: {e}")
            return None

    def set(self, prompt: str, model: str, response: Dict[str, Any], **kwargs) -> bool:
        """
        Store response in exact cache
        """
        try:
            # Create hash key
            cache_key = self._hash_prompt(prompt, model, **kwargs)

            # Create point with minimal vector (we don't use it)
            point = PointStruct(
                id=cache_key,
                vector=[0.0],  # Minimal vector
                payload={
                    "prompt": prompt,
                    "model": model,
                    "response": response,
                    "timestamp": time.time(),
                    "parameters": kwargs,
                },
            )

            # Store in Qdrant
            self.qdrant_client.upsert(
                collection_name=self.collection_name, points=[point]
            )

            logger.info("Stored exact cache entry")
            return True

        except Exception as e:
            logger.error(f"Error setting exact cache: {e}")
            return False

    def clear(self) -> bool:
        """
        Clear exact cache collection
        """
        try:
            self.qdrant_client.delete_collection(self.collection_name)
            logger.info(f"Cleared exact cache collection: {self.collection_name}")
            self._init_collection()
            return True
        except Exception as e:
            logger.error(f"Error clearing exact cache: {e}")
            return False

    def clear_cache(self, cache_type: str = "all") -> bool:
        """
        Clear cache collections.

        Args:
            cache_type: Type of cache to clear ("exact", "semantic", or "all")
                        For exact cache, only "exact" and "all" are supported

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if cache_type in ["exact", "all"]:
                self.qdrant_client.delete_collection(self.collection_name)
                logger.info(f"Cleared exact cache collection: {self.collection_name}")
                self._init_collection()
                return True
            elif cache_type == "semantic":
                # For semantic cache, we don't manage it here
                logger.info(
                    "Semantic cache is managed by LiteLLM, not clearing locally"
                )
                return True
            else:
                logger.warning(f"Unknown cache type: {cache_type}")
                return False
        except Exception as e:
            logger.error(f"Error clearing cache: {e}")
            return False
