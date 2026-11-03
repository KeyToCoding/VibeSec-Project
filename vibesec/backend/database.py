"""
VibeSec Database Layer
Handles scan result persistence and history retrieval with MongoDB.
Includes automatic fallback to in-memory store if MongoDB is offline.
Author: Kartikey Vishwakarma (NIELIT Gorakhpur Major Project)
"""

import os
import uuid
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger("vibesec.db")

MONGODB_URI = (os.getenv("MONGODB_URI") or "").strip()

# In-memory storage cache if MongoDB is offline
_IN_MEMORY_SCANS: Dict[str, Dict[str, Any]] = {}
_mongo_client = None
_db = None
_scans_collection = None
_mongo_unavailable = False


def get_db():
    global _mongo_client, _db, _scans_collection, _mongo_unavailable
    if _db is not None:
        return _scans_collection
    if _mongo_unavailable:
        return None
    if not MONGODB_URI:
        _mongo_unavailable = True
        logger.warning(
            "MONGODB_URI is not configured; using in-memory scan history. "
            "Server-side history will not persist across service restarts."
        )
        return None
    try:
        from pymongo import MongoClient
        _mongo_client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=2000)
        _mongo_client.server_info()
        _db = _mongo_client.get_database()
        _scans_collection = _db["scans"]
        logger.info("Connected to configured MongoDB database.")
        return _scans_collection
    except Exception as e:
        logger.warning(
            "MongoDB connection failed (%s). Using in-memory database store.",
            type(e).__name__,
        )
        return None


def save_scan_result(result: Dict[str, Any]) -> str:
    """Persist scan result into MongoDB or in-memory fallback."""
    scan_id = result.get("scan_id") or str(uuid.uuid4())
    result["scan_id"] = scan_id
    if "created_at" not in result:
        result["created_at"] = datetime.utcnow().isoformat()

    collection = get_db()
    if collection is not None:
        try:
            # Upsert into collection
            collection.update_one({"scan_id": scan_id}, {"$set": result}, upsert=True)
            logger.info(f"Saved scan {scan_id} to MongoDB")
            return scan_id
        except Exception as e:
            logger.error(f"Failed to save to MongoDB: {e}")

    # Fallback in-memory save
    _IN_MEMORY_SCANS[scan_id] = result
    logger.info(f"Saved scan {scan_id} to in-memory fallback store")
    return scan_id


def get_scan_history(limit: int = 20, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve the latest scans for history listing, strictly isolated per user session."""
    if not session_id:
        return []

    collection = get_db()
    if collection is not None:
        try:
            cursor = collection.find({"session_id": session_id}, {"_id": 0}).sort("created_at", -1).limit(limit)
            return list(cursor)
        except Exception as e:
            logger.error(f"Error fetching history from MongoDB: {e}")

    # Return in-memory scans matching user session sorted by created_at desc
    results = [s for s in _IN_MEMORY_SCANS.values() if s.get("session_id") == session_id]
    results.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return results[:limit]


def get_scan_by_id(scan_id: str) -> Optional[Dict[str, Any]]:
    """Fetch complete scan report by scan_id."""
    collection = get_db()
    if collection is not None:
        try:
            doc = collection.find_one({"scan_id": scan_id}, {"_id": 0})
            if doc:
                return doc
        except Exception as e:
            logger.error(f"Error fetching scan by id from MongoDB: {e}")

    return _IN_MEMORY_SCANS.get(scan_id)
