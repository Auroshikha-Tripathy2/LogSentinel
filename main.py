# main.py
from fastapi import FastAPI, HTTPException, Body, Depends, Query
from pydantic import BaseModel, Field, ValidationError
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import statistics
import re
import logging
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import os

# MongoDB imports
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, PyMongoError
from bson.objectid import ObjectId
from pymongo.collection import Collection

# Splunk SDK import
import splunklib.client as splunk_client
import splunklib.results as splunk_results

# Background task imports
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import threading
import time
import asyncio

# NLP Imports
import torch
import numpy as np # For array operations with embeddings
from sentence_transformers import SentenceTransformer # <--- CRITICAL IMPORT
from sklearn.cluster import MiniBatchKMeans
from sklearn.metrics.pairwise import cosine_similarity

# Other imports
import requests
import json


# --- Logging Configuration (MUST BE AT THE TOP AFTER IMPORTS) ---
# Set logging level to DEBUG for detailed diagnostics during debugging.
# Change to INFO for production.
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__) # 'logger' object is defined here


# --- MongoDB Configuration ---
MONGO_DETAILS = os.getenv("MONGO_DETAILS", "mongodb://localhost:27017")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "log_sentinel")
ANOMALIES_COLLECTION_NAME = "detected_anomalies"
PROFILES_COLLECTION_NAME = "entity_profiles"
GLOBAL_CLUSTERS_COLLECTION_NAME = "global_log_clusters"

client: Optional[MongoClient] = None
db = None
anomalies_collection: Optional[Collection] = None
profiles_collection: Optional[Collection] = None
global_clusters_collection: Optional[Collection] = None


# --- Splunk Configuration (for SDK) ---
SPLUNK_HOST = os.getenv("SPLUNK_HOST", "localhost")
SPLUNK_PORT = int(os.getenv("SPLUNK_PORT", 8089))
SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME", "auroshikha")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD", "Shikha@7328") # !!! REPLACE WITH YOUR ACTUAL SPLUNK WEB PASSWORD !!!

# --- Splunk HEC Configuration ---
SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL", "https://localhost:8088/services/collector")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "702bcf9a-c848-4b5c-a77b-92ece44b93a9") # !!! IMPORTANT: REPLACE WITH YOUR ACTUAL HEC TOKEN !!!
SPLUNK_HEC_INDEX = os.getenv("SPLUNK_HEC_INDEX", "main")
SPLUNK_HEC_SOURCE = os.getenv("SPLUNK_HEC_SOURCE", "log_sentinel_anomaly_tool")
SPLUNK_HEC_SOURCETYPE = os.getenv("SPLUNK_HEC_SOURCETYPE", "log_sentinel_anomalies")
SPLUNK_HEC_VERIFY_SSL = os.getenv("SPLUNK_HEC_VERIFY_SSL", "False").lower() in ('true', '1', 't', 'yes')


# --- NLP Model Initialization ---
NLP_MODEL_NAME = "sentence-transformers/all-mpnet-base-v2"

try:
    nlp_model = SentenceTransformer(NLP_MODEL_NAME)
    logger.info(f"Successfully loaded SentenceTransformer model: {NLP_MODEL_NAME}")
    logger.info(f"Type of nlp_model: {type(nlp_model)}") # Diagnostic print
except Exception as e:
    logger.critical(f"Failed to load SentenceTransformer model {NLP_MODEL_NAME}: {e}")
    logger.critical("Please ensure 'sentence-transformers' is installed (pip install sentence-transformers) and you have an internet connection for model download.")
    raise RuntimeError("NLP model failed to load during startup.")


# --- FastAPI App Initialization ---
app = FastAPI(
    title="LogSentinelAI++ Anomaly Detection Backend",
    description="API for real-time log anomaly detection using semantic profiling and clustering.",
    version="1.0.0",
)

# --- CORS Configuration ---
origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- In-Memory Storage for Entity Profiles ---
entity_profiles: Dict[str, 'ProfileModel'] = {}

# --- Global Log Embedding Clusters ---
global_kmeans_model: Optional[MiniBatchKMeans] = None
GLOBAL_NUM_CLUSTERS = 100
GLOBAL_CLUSTER_MIN_SAMPLES = 50
GLOBAL_CLUSTER_UPDATE_INTERVAL_HOURS = 24
GLOBAL_CLUSTER_ANOMALY_THRESHOLD = 0.8


# --- Helper Functions ---
def get_log_embedding(text: str) -> Optional[np.ndarray]:
    """Generates a sentence embedding for the given text."""
    if not text or nlp_model is None:
        logger.warning("Attempted to get embedding for empty text or NLP model not loaded.")
        return None
    try:
        embedding = nlp_model.encode(text, convert_to_numpy=True)
        logger.debug(f"Generated embedding for text (first 5 dims): {embedding[:5]}...")
        return embedding
    except Exception as e:
        logger.error(f"Error generating embedding for text: '{text[:50]}...' Error: {e}")
        return None


# --- Data Models ---

class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)

    @classmethod
    def __get_pydantic_json_schema__(cls, core_schema, handler):
        return {"type": "string"}

class LogEntry(BaseModel):
    """Represents a single log entry, potentially pulled from Splunk."""
    entity_id: str = Field(..., description="Unique identifier for the log-generating entity (user, service, script).")
    timestamp: datetime = Field(..., description="Timestamp of the log entry (ISO 8601 format, e.g., '2023-10-27T10:30:00').")
    log_content: str = Field(..., description="The actual content of the log line.")
    splunk_event_id: Optional[str] = Field(None, description="Unique ID from Splunk event.")
    id: Optional[PyObjectId] = Field(None, alias="_id")
    is_anomalous_true: Optional[bool] = Field(None, description="Ground truth label from parser (for evaluation only).")

    class Config:
        validate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}

class ProfileFeature(BaseModel):
    """Represents a statistical feature learned for an entity's log behavior."""
    mean: Optional[float] = None
    std_dev: Optional[float] = None
    min: Optional[float] = None
    max: Optional[float] = None
    most_common: Optional[List[str]] = None
    total_count: Optional[int] = None

class ProfileModel(BaseModel):
    """Represents the learned behavioral fingerprint for a log-generating entity."""
    id: Optional[PyObjectId] = Field(None, alias="_id")
    entity_id: str = Field(..., description="Unique identifier for the log-generating entity.")
    last_updated: datetime = Field(default_factory=datetime.now, description="Timestamp of the last profile update.")
    total_logs_processed: int = Field(0, description="Total number of logs used to build this profile.")
    log_length: ProfileFeature = Field(default_factory=ProfileFeature, description="Statistics on log content length.")
    word_count: ProfileFeature = Field(default_factory=ProfileFeature, description="Statistics on number of words in log content.")
    hour_of_day_distribution: Dict[str, int] = Field(default_factory=lambda: defaultdict(int), description="Distribution of log hours (0-23).")
    day_of_week_distribution: Dict[str, int] = Field(default_factory=lambda: defaultdict(int), description="Distribution of log days (0-6).")
    common_keywords: Dict[str, int] = Field(default_factory=lambda: defaultdict(int), description="Frequency of common keywords.")
    average_embedding: Optional[List[float]] = Field(None, description="Average semantic embedding of log content.")
    global_cluster_distribution: Dict[str, int] = Field(default_factory=lambda: defaultdict(int), description="Distribution of logs across global semantic clusters.")


    class Config:
        validate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}


class AnomalyDetectionResult(BaseModel):
    """Result of anomaly detection for a single log entry."""
    is_anomalous: bool = Field(False, description="True if the log entry is flagged as anomalous.")
    confidence_score: float = Field(0.0, description="Confidence score (0.0 to 1.0) of the anomaly.")
    reasons: List[str] = Field(default_factory=list, description="Reasons for flagging the log entry as anomalous.")
    detected_at: datetime = Field(default_factory=datetime.now, description="Timestamp when the anomaly was detected.")
    original_log_id: Optional[str] = Field(None, description="The MongoDB _id of the original raw log entry (if stored).")
    splunk_event_id: Optional[str] = Field(None, description="Unique ID from Splunk event (if applicable).")
    entity_id: str = Field(..., description="Entity ID associated with the anomaly.")
    anomaly_score: float = Field(0.0, description="Raw anomaly score from detection model.")
    is_anomalous_predicted: bool = Field(False, description="Predicted anomaly status (based on threshold).")

    id: Optional[PyObjectId] = Field(None, alias="_id")

    class Config:
        validate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}

class ForensicTimelineEntry(BaseModel):
    """Represents an entry in the forensic timeline."""
    timestamp: datetime
    log_content: str
    is_anomalous: bool
    confidence_score: float
    reasons: List[str]
    source_type: str # 'splunk_log' or 'anomaly'


# --- MongoDB Connection Lifecycle Events ---
@app.on_event("startup")
async def startup_db_client():
    global client, db, anomalies_collection, profiles_collection, global_clusters_collection, global_kmeans_model
    try:
        client = MongoClient(MONGO_DETAILS)
        client.admin.command('ping') # Test connection
        db = client[MONGO_DB_NAME]
        anomalies_collection = db[ANOMALIES_COLLECTION_NAME]
        profiles_collection = db[PROFILES_COLLECTION_NAME]
        global_clusters_collection = db[GLOBAL_CLUSTERS_COLLECTION_NAME]

        anomalies_collection.create_index("entity_id")
        anomalies_collection.create_index("detected_at")
        profiles_collection.create_index("entity_id", unique=True)

        logger.info(f"Successfully connected to MongoDB at {MONGO_DETAILS}")
        logger.info(f"Using database: {MONGO_DB_NAME}, anomalies collection: {ANOMALIES_COLLECTION_NAME}")
        logger.info(f"Using profiles collection: {PROFILES_COLLECTION_NAME}")
        logger.info(f"Using global clusters collection: {GLOBAL_CLUSTERS_COLLECTION_NAME}")

        # Load existing profiles from MongoDB into memory
        for profile_doc in profiles_collection.find():
            try:
                profile_id = str(profile_doc['_id'])
                profile_doc.pop('_id', None)
                profile = ProfileModel(**profile_doc)
                profile.id = PyObjectId(profile_id)
                entity_profiles[profile.entity_id] = profile
                logger.info(f"Loaded profile for entity: {profile.entity_id}")
            except ValidationError as ve:
                logger.error(f"Error loading profile from DB: {profile_doc}. Validation Error: {ve}")
            except Exception as e:
                logger.error(f"Unexpected error loading profile {profile_doc}: {e}")

        # Load global KMeans model if it exists in DB
        global_kmeans_doc = global_clusters_collection.find_one({"_id": "global_kmeans_model"})
        if global_kmeans_doc and 'centroids' in global_kmeans_doc and 'n_clusters' in global_kmeans_doc:
            try:
                global_kmeans_model = MiniBatchKMeans(
                    n_clusters=global_kmeans_doc['n_clusters'],
                    random_state=42, # Ensure reproducibility
                    batch_size=256, # Default batch size
                    n_init='auto' # Auto init
                )
                global_kmeans_model.cluster_centers_ = np.array(global_kmeans_doc['centroids'])
                logger.info(f"Loaded global KMeans model with {global_kmeans_model.n_clusters} clusters from DB.")
            except Exception as e:
                logger.error(f"Failed to load global KMeans model from DB: {e}")
                global_kmeans_model = None
        else:
            logger.info("No global KMeans model found in DB. Will train on first sufficient data.")


        try:
            # Splunk SDK connection check
            splunk_service = splunk_client.connect(
                host=SPLUNK_HOST,
                port=SPLUNK_PORT,
                username=SPLUNK_USERNAME,
                password=SPLUNK_PASSWORD,
                scheme="https" # Use https for Splunk management port unless configured otherwise
            )
            logger.info(f"Successfully connected to Splunk (SDK) at {SPLUNK_HOST}:{SPLUNK_PORT}")
        except Exception as splunk_e:
            logger.error(f"Could not connect to Splunk (SDK): {splunk_e}. Splunk integration via SDK will be limited.")
        
        # Test HEC connection
        if SPLUNK_HEC_TOKEN != "702bcf9a-c848-4b5c-a77b-92ece44b93a9": # Check if token is actually set
            try:
                response = requests.post(
                    SPLUNK_HEC_URL,
                    headers={'Authorization': f'Splunk {SPLUNK_HEC_TOKEN}'},
                    json={"event": {"message": "Log Sentinel HEC test event", "status": "startup_check"}},
                    verify=not SPLUNK_HEC_VERIFY_SSL # Use 'not' because verify=False means don't verify
                )
                response.raise_for_status()
                logger.info(f"Successfully sent test event to Splunk HEC at {SPLUNK_HEC_URL}")
            except requests.exceptions.ConnectionError as ce:
                logger.warning(f"Could not connect to Splunk HEC at {SPLUNK_HEC_URL}: {ce}. Anomalies will not be sent to Splunk.")
            except requests.exceptions.HTTPError as he:
                logger.warning(f"Splunk HEC returned HTTP error {he.response.status_code} for {SPLUNK_HEC_URL}: {he.response.text}. Check HEC token and settings.")
            except Exception as e:
                logger.warning(f"An unexpected error occurred during Splunk HEC test: {e}. Anomalies may not be sent to Splunk.")
        else:
            logger.warning("Splunk HEC token is not configured. HEC test skipped. Anomalies will not be sent to Splunk.")


        # Automated Splunk ingestion (if applicable)
        scheduler = BackgroundScheduler()
        scheduler.add_job(
            automated_splunk_ingestion, # This is a conceptual function, ensure it's defined
            trigger=IntervalTrigger(minutes=10),
            id='automated_splunk_ingestion_job',
            replace_existing=True
        )
        scheduler.start()
        logger.info("Background Splunk ingestion job started.")

    except ConnectionFailure as e:
        logger.error(f"Could not connect to MongoDB: {e}")
        logger.error("Application will run in demo mode without database persistence.")
        client = None
        db = None
        anomalies_collection = None
        profiles_collection = None
        global_clusters_collection = None
        global_kmeans_model = None
    except Exception as e:
        logger.exception(f"An unexpected error occurred during MongoDB or Splunk startup: {e}")
        logger.error("Application will run in demo mode without database persistence and limited Splunk integration.")
        client = None
        db = None
        anomalies_collection = None
        profiles_collection = None
        global_clusters_collection = None
        global_kmeans_model = None


@app.on_event("shutdown")
async def shutdown_db_client():
    """Closes the MongoDB connection and shuts down the scheduler when FastAPI application shuts down."""
    global client
    if client:
        client.close()
        logger.info("MongoDB connection closed.")
    
    # Safely shut down the scheduler
    scheduler = BackgroundScheduler() # Re-instantiate to get the same scheduler
    if scheduler.running:
        scheduler.shutdown(wait=False) # wait=False to prevent blocking
        logger.info("Background scheduler shut down.")


# --- Dependency to get MongoDB collections ---
def get_anomalies_collection():
    if anomalies_collection is None:
        logger.warning("Attempting to get anomalies collection, but MongoDB not available. Using None.")
        return None
    return anomalies_collection

def get_profiles_collection():
    if profiles_collection is None:
        logger.warning("Attempting to get profiles collection, but MongoDB not available. Using None.")
        return None
    return profiles_collection

def get_global_clusters_collection(): # New dependency
    if global_clusters_collection is None:
        logger.warning("Attempting to get global clusters collection, but MongoDB not available. Using None.")
        return None
    return global_clusters_collection

# --- Feature Extraction Helpers ---
def extract_features(log: LogEntry) -> Dict[str, Any]:
    """Extracts features from a single log entry, including NLP embedding."""
    try:
        dt_obj = log.timestamp # Timestamp is already a datetime object from Pydantic parsing
    except AttributeError: # Fallback if for some reason it's not datetime
        try:
            dt_obj = datetime.fromisoformat(log.timestamp)
        except ValueError:
            logger.warning(f"Invalid timestamp format for log_id {log.entity_id}: {log.timestamp}. Using current time.")
            dt_obj = datetime.now()

    log_len = len(log.log_content)
    word_count = len(log.log_content.split())
    hour_of_day = str(dt_obj.hour)
    day_of_week = str(dt_obj.weekday())

    keywords = [word.lower() for word in re.findall(r'\b\w+\b', log.log_content) if len(word) > 3]

    log_embedding = get_log_embedding(log.log_content) # This returns np.ndarray now

    return {
        "log_len": log_len,
        "word_count": word_count,
        "hour_of_day": hour_of_day,
        "day_of_week": day_of_week,
        "keywords": keywords,
        "timestamp_dt": dt_obj,
        "log_embedding": log_embedding # np.ndarray
    }

# --- Global Clustering Training ---
@app.post("/profile/train-global-clusters")
async def train_global_semantic_clusters_api( # Renamed to avoid confusion with internal func
    logs: List[LogEntry],
    global_clusters_db_collection: Collection = Depends(get_global_clusters_collection)
):
    """
    Trains global semantic clusters based on log embeddings from provided normal logs.
    This should be run once with a large set of representative normal logs.
    """
    global global_kmeans_model
    
    if nlp_model is None:
        raise HTTPException(status_code=500, detail="NLP model not loaded. Cannot train global clusters.")

    embeddings_to_cluster = []
    for log in logs:
        embedding = get_log_embedding(log.log_content)
        if embedding is not None: # Ensure embedding was successfully generated
            embeddings_to_cluster.append(embedding)
    
    if len(embeddings_to_cluster) < GLOBAL_CLUSTER_MIN_SAMPLES:
        raise HTTPException(
            status_code=400,
            detail=f"Not enough samples ({len(embeddings_to_cluster)}) to train global clusters. Need at least {GLOBAL_CLUSTER_MIN_SAMPLES}."
        )
    
    embeddings_array = np.array(embeddings_to_cluster)
    
    logger.info(f"Starting global KMeans clustering with {len(embeddings_array)} samples into {GLOBAL_NUM_CLUSTERS} clusters...")
    try:
        global_kmeans_model = MiniBatchKMeans(
            n_clusters=GLOBAL_NUM_CLUSTERS,
            random_state=42, # For reproducibility
            batch_size=256, # Process in batches for large datasets
            n_init='auto' # Automatically determine the number of initializations
        )
        global_kmeans_model.fit(embeddings_array)
        
        # Save cluster centroids to MongoDB
        if global_clusters_db_collection is not None:
            global_clusters_db_collection.update_one(
                {"_id": "global_kmeans_model"},
                {"$set": {
                    "n_clusters": GLOBAL_NUM_CLUSTERS,
                    "centroids": global_kmeans_model.cluster_centers_.tolist()
                }},
                upsert=True
            )
            logger.info(f"Global KMeans model with {GLOBAL_NUM_CLUSTERS} clusters saved to MongoDB.")
        else:
            logger.warning("MongoDB global clusters collection not available. Global KMeans model not persisted.")

        logger.info("Global KMeans clustering complete.")
        return {"message": f"Successfully trained global semantic clusters ({GLOBAL_NUM_CLUSTERS} clusters)."}
    except Exception as e:
        logger.error(f"Error training global KMeans clusters: {e}")
        raise HTTPException(status_code=500, detail=f"Error training global clusters: {e}")


# --- Behavioral Profiling (Learning) ---
@app.post("/profile/learn")
async def learn_behavior(
    logs: List[LogEntry],
    profiles_db_collection: Collection = Depends(get_profiles_collection)
):
    """
    Learns normal behavioral fingerprints for log-generating entities.
    This endpoint simulates the 'training' phase.
    """
    if profiles_db_collection is None:
        logger.warning("MongoDB profiles collection not available. Profiles will not be persisted.")
    
    for log in logs:
        entity_id = log.entity_id
        features = extract_features(log)

        if entity_id not in entity_profiles:
            profile = ProfileModel(entity_id=entity_id, total_logs_processed=0)
            entity_profiles[entity_id] = profile
        else:
            profile = entity_profiles[entity_id]

        profile.total_logs_processed += 1
        current_logs_processed = profile.total_logs_processed
        
        # Log Length
        if current_logs_processed == 1:
            profile.log_length.mean = float(features["log_len"])
            profile.log_length.min = float(features["log_len"])
            profile.log_length.max = float(features["log_len"])
        else:
            old_mean_len = profile.log_length.mean or 0.0
            new_mean_len = (old_mean_len * (current_logs_processed - 1) + features["log_len"]) / current_logs_processed
            profile.log_length.mean = new_mean_len
            profile.log_length.min = min(profile.log_length.min or features["log_len"], features["log_len"])
            profile.log_length.max = max(profile.log_length.max or features["log_len"], features["log_len"])

        # Word Count
        if current_logs_processed == 1:
            profile.word_count.mean = float(features["word_count"])
            profile.word_count.min = float(features["word_count"])
            profile.word_count.max = float(features["word_count"])
        else:
            old_mean_wc = profile.word_count.mean or 0.0
            new_mean_wc = (old_mean_wc * (current_logs_processed - 1) + features["word_count"]) / current_logs_processed
            profile.word_count.mean = new_mean_wc
            profile.word_count.min = min(profile.word_count.min or features["word_count"], features["word_count"])
            profile.word_count.max = max(profile.word_count.max or features["word_count"], features["word_count"])

        # Update categorical distributions
        profile.hour_of_day_distribution[features["hour_of_day"]] += 1
        profile.day_of_week_distribution[features["day_of_week"]] += 1

        # Update common keywords
        for keyword in features["keywords"]:
            profile.common_keywords[keyword] += 1
        
        # Update average embedding
        if features["log_embedding"] is not None:
            new_embedding_tensor = torch.tensor(features["log_embedding"])
            if profile.average_embedding is None:
                profile.average_embedding = new_embedding_tensor.tolist()
            else:
                old_embedding_tensor = torch.tensor(profile.average_embedding)
                profile.average_embedding = ((old_embedding_tensor * (current_logs_processed - 1) + new_embedding_tensor) / current_logs_processed).tolist()

            # New: Update entity's global cluster distribution
            if global_kmeans_model is not None:
                cluster_label = global_kmeans_model.predict(new_embedding_tensor.reshape(1, -1))[0]
                profile.global_cluster_distribution[str(cluster_label)] += 1


        profile.last_updated = datetime.now()

        profile_data_dict = profile.dict(by_alias=True, exclude_none=True)
        if profile_data_dict.get("_id") is None:
            profile_data_dict.pop("_id", None)

        try:
            if profiles_db_collection is not None:
                result = profiles_db_collection.update_one(
                    {"entity_id": entity_id},
                    {"$set": profile_data_dict},
                    upsert=True
                )
                if result.upserted_id:
                    profile.id = PyObjectId(result.upserted_id)
                    logger.info(f"Inserted new profile for entity '{entity_id}' with _id: {result.upserted_id}")
                else:
                    logger.debug(f"Updated profile for entity '{entity_id}'. Matched: {result.matched_count}, Modified: {result.modified_count}")
        except PyMongoError as e:
            logger.error(f"MongoDB error saving profile for entity '{entity_id}': {e}")
        except Exception as e:
            logger.error(f"Unexpected error saving profile for entity '{entity_id}': {e}")


    logger.info(f"Learned profiles for {len(logs)} logs.")
    return {"message": f"Successfully learned from {len(logs)} log entries."}


@app.get("/profile/{entity_id}")
async def get_profile(
    entity_id: str,
    profiles_db_collection: Collection = Depends(get_profiles_collection)
):
    """Retrieves the learned profile for a specific entity."""
    profile = entity_profiles.get(entity_id)

    if not profile and profiles_db_collection is not None:
        profile_doc = profiles_db_collection.find_one({"entity_id": entity_id})
        if profile_doc:
            try:
                profile_id = str(profile_doc['_id'])
                profile_doc.pop('_id', None)
                profile = ProfileModel(**profile_doc)
                profile.id = PyObjectId(profile_id)
                entity_profiles[entity_id] = profile
                logger.info(f"Fetched profile for entity '{entity_id}' from DB.")
            except ValidationError as ve:
                logger.error(f"Error validating profile from DB for entity '{entity_id}': {ve}")
                profile = None
            except Exception as e:
                logger.error(f"Unexpected error fetching profile from DB for entity '{entity_id}': {e}")
                profile = None


    if not profile:
        raise HTTPException(status_code=404, detail="Entity profile not found. Please train first.")
    return profile


# --- Anomaly Detection Logic (Internal Function) ---
async def _perform_anomaly_detection(log: LogEntry) -> AnomalyDetectionResult:
    """
    Internal function to perform anomaly detection on a single log entry.
    This is called by the ingestion endpoint.
    """
    entity_id = log.entity_id
    profile = entity_profiles.get(entity_id)

    features = extract_features(log)
    logger.debug(f"[DEBUG] Features for log (entity_id={entity_id}): {features}")
    if log.is_anomalous_true is not None:
        logger.debug(f"[DEBUG] Ground truth is_anomalous_true: {log.is_anomalous_true}")

    if not profile:
        logger.warning(f"No profile found for entity '{entity_id}'. Cannot perform detailed anomaly detection. Labeling as normal.")
        return AnomalyDetectionResult(
            is_anomalous=False,
            is_anomalous_predicted=False,
            confidence_score=0.0,
            reasons=["No learned profile for this entity."],
            original_log_id=str(log.id) if log.id else None,
            splunk_event_id=log.splunk_event_id,
            entity_id=log.entity_id,
            anomaly_score=0.0,
            _id=None
        )

    is_anomalous_predicted = False
    reasons = []
    confidence_score_sum = 0.0
    raw_anomaly_score = 0.0

    # --- Anomaly Rules/Checks ---
    
    # 1. Log Length Anomaly
    if profile.log_length.min is not None and profile.log_length.max is not None:
        if not (profile.log_length.min * 0.95 <= features["log_len"] <= profile.log_length.max * 1.05):
            reasons.append(f"Log length ({features['log_len']}) deviates from normal range ({profile.log_length.min:.1f}-{profile.log_length.max:.1f}).")
            confidence_score_sum += 0.5
            raw_anomaly_score += 0.2

    # 2. Word Count Anomaly
    if profile.word_count.min is not None and profile.word_count.max is not None:
        if not (profile.word_count.min * 0.95 <= features["word_count"] <= profile.word_count.max * 1.05):
            reasons.append(f"Word count ({features['word_count']}) deviates from normal range ({profile.word_count.min:.1f}-{profile.word_count.max:.1f}).")
            confidence_score_sum += 0.5
            raw_anomaly_score += 0.2

    # 3. Timestamp Pattern Anomaly (Hour of Day)
    total_hours = sum(profile.hour_of_day_distribution.values())
    if total_hours > 0:
        current_hour_freq = profile.hour_of_day_distribution.get(features["hour_of_day"], 0)
        if current_hour_freq / total_hours < 0.01 and total_hours > 50:
            reasons.append(f"Log timestamp is in an unusual hour ({features['hour_of_day']}:00) for this entity.")
            confidence_score_sum += 0.2
            raw_anomaly_score += 0.1

    # 4. Keyword Anomaly
    profile_keywords_set = set(profile.common_keywords.keys())
    new_keywords = [k for k in features["keywords"] if k not in profile_keywords_set]
    if new_keywords:
        reasons.append(f"New or unusual keywords detected: {', '.join(new_keywords[:5])}.")
        confidence_score_sum += 0.4
        raw_anomaly_score += 0.3

    # 5. Semantic Similarity Anomaly (Similarity to entity's average embedding)
    if features["log_embedding"] is not None and profile.average_embedding is not None:
        current_embedding = features["log_embedding"]
        profile_avg_embedding = np.array(profile.average_embedding)
        
        # Ensure embeddings are not all zeros or identical before calculating similarity
        if np.all(current_embedding == 0) or np.all(profile_avg_embedding == 0) or np.all(current_embedding == profile_avg_embedding):
            logger.warning(f"Skipping semantic similarity for {entity_id} due to zero/identical embeddings.")
            cosine_sim = 1.0 # Treat as perfectly similar if embeddings are problematic
        else:
            cosine_sim = cosine_similarity(current_embedding.reshape(1, -1), profile_avg_embedding.reshape(1, -1))[0][0]
            logger.debug(f"Semantic similarity for {entity_id}: {cosine_sim:.4f}")
        
        semantic_similarity_threshold = 0.75

        if cosine_sim < semantic_similarity_threshold:
            reasons.append(f"Log content semantic similarity ({cosine_sim:.2f}) to entity's profile is low (threshold: {semantic_similarity_threshold}).")
            confidence_score_sum += 0.7
            raw_anomaly_score += (1.0 - cosine_sim) * 0.5

    # 6. Semantic Drift / Impersonation Anomaly (Unusual global cluster for entity)
    if global_kmeans_model is not None and features["log_embedding"] is not None:
        current_embedding_np = features["log_embedding"].reshape(1, -1)
        
        # Check if embeddings are valid before prediction
        if not np.isfinite(current_embedding_np).all():
            logger.warning(f"Skipping global cluster prediction for {entity_id} due to non-finite embeddings.")
        else:
            try:
                cluster_label = global_kmeans_model.predict(current_embedding_np)[0]
                logger.debug(f"Log for {entity_id} assigned to global cluster: {cluster_label}")
                total_entity_logs_with_clusters = sum(profile.global_cluster_distribution.values())

                if total_entity_logs_with_clusters > GLOBAL_CLUSTER_MIN_SAMPLES:
                    cluster_freq_for_entity = profile.global_cluster_distribution.get(str(cluster_label), 0) / total_entity_logs_with_clusters
                    unusual_cluster_threshold = 0.01
                    
                    if cluster_freq_for_entity < unusual_cluster_threshold:
                        reasons.append(f"Log's semantic type (cluster {cluster_label}) is unusually rare for entity ({cluster_freq_for_entity:.2f}%).")
                        confidence_score_sum += 0.6
                        raw_anomaly_score += 0.4
            except Exception as e:
                logger.error(f"Error predicting global cluster for {entity_id}: {e}")


    # 7. Time-series Anomaly (Gap since last log)
    expected_max_gap_seconds = 3600 * 24 * 7
    if profile.total_logs_processed > 10 and (datetime.now() - profile.last_updated).total_seconds() > expected_max_gap_seconds:
        reasons.append(f"Unusually long gap ({(datetime.now() - profile.last_updated).total_seconds() / 3600:.1f} hours) since last log from this entity.")
        confidence_score_sum += 0.2
        raw_anomaly_score += 0.1


    # Normalize confidence score
    max_possible_confidence_sum = 0.5 + 0.5 + 0.2 + 0.4 + 0.7 + 0.6 + 0.2
    normalized_confidence_score = min(confidence_score_sum / max_possible_confidence_sum, 1.0) if max_possible_confidence_sum > 0 else 0.0
    
    # Decide if anomalous based on a final threshold for raw_anomaly_score
    if raw_anomaly_score > 0.5:
        is_anomalous_predicted = True

    logger.info(f"Anomaly detection for entity {entity_id}: Predicted_Anomalous={is_anomalous_predicted}, Raw_Score={raw_anomaly_score:.2f}, Reasons={reasons}")

    return AnomalyDetectionResult(
        is_anomalous=log.is_anomalous_true if log.is_anomalous_true is not None else is_anomalous_predicted,
        is_anomalous_predicted=is_anomalous_predicted,
        confidence_score=normalized_confidence_score,
        reasons=reasons,
        original_log_id=str(log.id) if log.id else None,
        splunk_event_id=log.splunk_event_id,
        entity_id=log.entity_id,
        detected_at=datetime.now(),
        anomaly_score=raw_anomaly_score,
        _id=None
    )


@app.post("/detect/anomaly")
async def detect_anomaly(log: LogEntry):
    """
    Detects if a single log entry is anomalous.
    """
    logger.debug(f"Received log for anomaly detection: {log}")
    result = await _perform_anomaly_detection(log)
    logger.debug(f"Anomaly detection result: {result}")
    
    if result.is_anomalous_predicted and anomalies_collection is not None:
        try:
            anomaly_data_dict = result.dict(by_alias=True, exclude_none=True)
            if anomaly_data_dict.get("_id") is None:
                anomaly_data_dict.pop("_id", None)
            
            inserted_id = anomalies_collection.insert_one(anomaly_data_dict).inserted_id
            logger.info(f"Stored detected anomaly in MongoDB: {inserted_id}")
            result.id = PyObjectId(inserted_id)
        except PyMongoError as e:
            logger.error(f"MongoDB error storing anomaly for entity '{result.entity_id}': {e}")
        except Exception as e:
            logger.error(f"Unexpected error storing anomaly for entity '{result.entity_id}': {e}")

    if result.is_anomalous_predicted:
        hec_send_data = result.dict(by_alias=True)
        if hec_send_data.get('id'):
            hec_send_data['id'] = str(hec_send_data.pop('id'))
        threading.Thread(target=send_to_splunk_hec, args=(hec_send_data,)).start()

    return result

@app.post("/detect/batch")
async def detect_batch_anomalies(logs: List[LogEntry]):
    """
    Detects anomalies for a batch of log entries.
    """
    results: List[AnomalyDetectionResult] = []
    for log in logs:
        result = await _perform_anomaly_detection(log)
        results.append(result)

        if result.is_anomalous_predicted and anomalies_collection is not None:
            try:
                anomaly_data_dict = result.dict(by_alias=True, exclude_none=True)
                if anomaly_data_dict.get("_id") is None:
                    anomaly_data_dict.pop("_id", None)
                anomalies_collection.insert_one(anomaly_data_dict)
                logger.debug(f"Stored detected anomaly for entity '{result.entity_id}' in batch.")
            except PyMongoError as e:
                logger.error(f"MongoDB error storing batch anomaly for entity '{result.entity_id}': {e}")
            except Exception as e:
                logger.error(f"Unexpected error storing batch anomaly for entity '{result.entity_id}': {e}")
            
            hec_send_data = result.dict(by_alias=True)
            if hec_send_data.get('id'):
                hec_send_data['id'] = str(hec_send_data.pop('id'))
            threading.Thread(target=send_to_splunk_hec, args=(hec_send_data,)).start()

    return results


# --- Function to send anomalies to Splunk HEC ---
def send_to_splunk_hec(anomaly_data: Dict[str, Any]):
    """
    Sends detected anomaly data to Splunk via HTTP Event Collector (HEC).
    """
    if not SPLUNK_HEC_TOKEN or SPLUNK_HEC_TOKEN == "YOUR_HEC_TOKEN_HERE" or not SPLUNK_HEC_URL:
        logger.warning("Splunk HEC token or URL not configured. Skipping sending anomaly to Splunk.")
        return

    hec_event = {
        "event": anomaly_data,
        "sourcetype": SPLUNK_HEC_SOURCETYPE,
        "source": SPLUNK_HEC_SOURCE,
        "index": SPLUNK_HEC_INDEX,
        "host": "log_sentinel_backend",
        "time": datetime.now().timestamp()
    }

    try:
        headers = {'Authorization': f'Splunk {SPLUNK_HEC_TOKEN}'}
        response = requests.post(
            SPLUNK_HEC_URL,
            headers=headers,
            json=hec_event,
            verify=not SPLUNK_HEC_VERIFY_SSL
        )
        response.raise_for_status()
        logger.info(f"Successfully sent anomaly for entity '{anomaly_data.get('entity_id')}' to Splunk HEC.")
    except requests.exceptions.ConnectionError as ce:
        logger.error(f"Failed to connect to Splunk HEC at {SPLUNK_HEC_URL}: {ce}")
    except requests.exceptions.HTTPError as he:
        logger.error(f"Splunk HEC returned HTTP error {he.response.status_code} for {SPLUNK_HEC_URL}: {he.response.text}. Check HEC token and settings.")
    except Exception as e:
        logger.error(f"An unexpected error occurred while sending to Splunk HEC: {e}")


# --- New Endpoint: Fetch and Analyze Logs from Splunk (Conceptual) ---
def get_splunk_service():
    """Returns a Splunk service object for SDK operations."""
    try:
        service = splunk_client.connect(
            host=SPLUNK_HOST,
            port=SPLUNK_PORT,
            username=SPLUNK_USERNAME,
            password=SPLUNK_PASSWORD,
            scheme="https"
        )
        return service
    except Exception as e:
        logger.error(f"Failed to connect to Splunk SDK at {SPLUNK_HOST}:{SPLUNK_PORT}: {e}")
        raise HTTPException(status_code=500, detail="Failed to connect to Splunk SDK.")

def automated_splunk_ingestion_wrapper():
    """Wrapper to run automated_splunk_ingestion in the background."""
    asyncio.run(automated_splunk_ingestion())

async def automated_splunk_ingestion():
    """
    Periodically fetches logs from Splunk, performs anomaly detection,
    and stores/sends anomalies. This runs as a background job.
    """
    logger.info("Starting automated Splunk log ingestion and anomaly detection.")
    try:
        service = get_splunk_service()
        splunk_query = "index=main | head 100"
        
        job = service.jobs.create(
            splunk_query,
            earliest_time="-10m",
            latest_time="now",
            exec_mode="blocking"
        )
        
        reader = splunk_results.ResultsReader(job.results())
        processed_count = 0
        anomalies_found = 0

        logs_to_process_batch = []
        for result in reader:
            if isinstance(result, dict):
                entity_id = result.get('user') or result.get('host') or result.get('source') or 'unknown'
                timestamp_str = result.get('_time')
                try:
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00')) if timestamp_str else datetime.now()
                except ValueError:
                    timestamp = datetime.now()

                log_content = result.get('_raw') or str(result)
                log_entry = LogEntry(
                    entity_id=entity_id,
                    timestamp=timestamp,
                    log_content=log_content,
                    splunk_event_id=result.get('sid')
                )
                logs_to_process_batch.append(log_entry)

                if len(logs_to_process_batch) >= BATCH_SIZE:
                    batch_results = await detect_batch_anomalies(logs_to_process_batch)
                    processed_count += len(logs_to_process_batch)
                    anomalies_found += sum(1 for r in batch_results if r.is_anomalous_predicted)
                    logs_to_process_batch = []

        if logs_to_process_batch:
            batch_results = await detect_batch_anomalies(logs_to_process_batch)
            processed_count += len(logs_to_process_batch)
            anomalies_found += sum(1 for r in batch_results if r.is_anomalous_predicted)

        logger.info(f"[Automated Splunk Ingestion] Processed {processed_count} logs, found {anomalies_found} anomalies.")
    except Exception as e:
        logger.exception(f"[Automated Splunk Ingestion] Error: {e}")

@app.post("/splunk/fetch-and-analyze-logs")
async def fetch_and_analyze_splunk_logs(
    splunk_query: str = Body(..., embed=True),
    earliest_time: str = Body("-24h", embed=True),
    latest_time: str = Body("now", embed=True),
    anomalies_db_collection: Collection = Depends(get_anomalies_collection)
):
    """
    Fetch logs from Splunk, run anomaly detection, and store anomalies in MongoDB.
    Also sends detected anomalies to Splunk HEC.
    """
    logger.info(f"Fetching and analyzing Splunk logs with query: '{splunk_query}' from {earliest_time} to {latest_time}")
    service = get_splunk_service()
    job = service.jobs.create(
        splunk_query,
        earliest_time=earliest_time,
        latest_time="now",
        exec_mode="blocking"
    )
    reader = splunk_results.ResultsReader(job.results())
    processed_count = 0
    anomalies_found = 0

    logs_to_process_batch = []
    for result in reader:
        if isinstance(result, dict):
            entity_id = result.get('user') or result.get('host') or result.get('source') or 'unknown'
            timestamp_str = result.get('_time')
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00')) if timestamp_str else datetime.now()
            except ValueError:
                timestamp = datetime.now()
            log_content = result.get('_raw') or str(result)
            
            log_entry = LogEntry(
                entity_id=entity_id,
                timestamp=timestamp,
                log_content=log_content,
                splunk_event_id=result.get('sid')
            )
            logs_to_process_batch.append(log_entry)

            if len(logs_to_process_batch) >= BATCH_SIZE:
                batch_results = await detect_batch_anomalies(logs_to_process_batch)
                processed_count += len(logs_to_process_batch)
                anomalies_found += sum(1 for r in batch_results if r.is_anomalous_predicted)
                logs_to_process_batch = []

    if logs_to_process_batch:
        batch_results = await detect_batch_anomalies(logs_to_process_batch)
        processed_count += len(logs_to_process_batch)
        anomalies_found += sum(1 for r in batch_results if r.is_anomalous_predicted)

    logger.info(f"Finished fetching and analyzing Splunk logs. Processed {processed_count} logs, found {anomalies_found} anomalies.")
    return {"message": f"Processed {processed_count} logs, found {anomalies_found} anomalies."}


# --- Forensic Timeline Endpoint ---
@app.get("/forensic/timeline/{entity_id}")
async def get_forensic_timeline(
    entity_id: str,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    anomalies_db_collection: Collection = Depends(get_anomalies_collection)
) -> List[ForensicTimelineEntry]:
    """
    Provides a forensic timeline for a given entity, combining fetched Splunk logs (conceptually)
    and detected anomalies from MongoDB.
    """
    logger.info(f"Generating forensic timeline for entity: {entity_id}")
    timeline_entries: List[ForensicTimelineEntry] = []

    # Mock raw logs for timeline (replace with actual Splunk fetching if needed)
    mock_raw_logs_for_timeline = [
        {"timestamp": datetime.now() - timedelta(hours=5, minutes=30), "log_content": "User logged in successfully from 192.168.1.100", "entity_id": "user_alice"},
        {"timestamp": datetime.now() - timedelta(hours=4, minutes=15), "log_content": "Command executed: ls -la /var/log", "entity_id": "user_alice"},
        {"timestamp": datetime.now() - timedelta(hours=3, minutes=0), "log_content": "Web server process started.", "entity_id": "service_webserver"},
    ]
    for log_data in mock_raw_logs_for_timeline:
        if log_data["entity_id"] == entity_id:
            entry_dt = log_data["timestamp"]
            if start_time and entry_dt < datetime.fromisoformat(start_time): continue
            if end_time and entry_dt > datetime.fromisoformat(end_time): continue
            timeline_entries.append(ForensicTimelineEntry(
                timestamp=entry_dt,
                log_content=log_data["log_content"],
                is_anomalous=False,
                confidence_score=0.0,
                reasons=[],
                source_type='splunk_log'
            ))

    # Fetch anomalies from MongoDB
    if anomalies_db_collection is not None:
        anomaly_query: Dict[str, Any] = {"entity_id": entity_id}
        if start_time:
            anomaly_query["detected_at"] = {"$gte": datetime.fromisoformat(start_time)}
        if end_time:
            if "detected_at" not in anomaly_query:
                anomaly_query["detected_at"] = {}
            anomaly_query["detected_at"]["$lte"] = datetime.fromisoformat(end_time)

        anomalies_cursor = anomalies_db_collection.find(anomaly_query).sort("detected_at", 1)
        for anomaly_doc in anomalies_cursor:
            timeline_entries.append(ForensicTimelineEntry(
                timestamp=anomaly_doc.get("detected_at"),
                log_content=f"[ANOMALY] {anomaly_doc.get('reasons', ['Unknown anomaly']).pop()}",
                is_anomalous=True,
                confidence_score=anomaly_doc.get("confidence_score", 0.0),
                reasons=anomaly_doc.get("reasons", []),
                source_type='anomaly'
            ))
    else:
        logger.warning("MongoDB anomalies collection not available. Forensic timeline will only show mock logs.")

    # Sort the combined timeline by timestamp
    return sorted(timeline_entries, key=lambda x: x.timestamp)

# --- Root Endpoint ---
@app.get("/")
async def read_root():
    return {"message": "Cybersecurity Log Anomaly Detection Backend is running and connected to MongoDB (with conceptual Splunk integration)!"}

# --- To Run This Application ---
# 1. Ensure MongoDB is running on your system (e.g., via Docker or a local installation).
#    If using Docker: docker run -p 27017:27017 --name mongo_db -d mongo
# 2. Ensure Splunk is running and HEC is configured (see guide above).
# 3. Install dependencies:
#    pip install fastapi uvicorn pydantic pymongo sentence-transformers scikit-learn matplotlib numpy requests apscheduler splunk-sdk
#    (Note: 'torch' is typically installed with sentence-transformers or via its own instructions, ensure it's compatible)
# 4. Set environment variables for Splunk SDK and HEC:
#    (Windows PowerShell)
#    $env:SPLUNK_HOST="your_splunk_sdk_ip"
#    $env:SPLUNK_PORT="8089"
#    $env:SPLUNK_USERNAME="your_splunk_username"
#    $env:SPLUNK_PASSWORD="your_splunk_password"
#    $env:SPLUNK_HEC_URL="https://your_splunk_hec_ip:8088/services/collector"
#    $env:SPLUNK_HEC_TOKEN="YOUR_ACTUAL_HEC_TOKEN_HERE" # !!! IMPORTANT: REPLACE THIS !!!
#    $env:SPLUNK_HEC_INDEX="main"
#    $env:SPLUNK_HEC_SOURCE="log_sentinel_anomaly_tool"
#    $env:SPLUNK_HEC_SOURCETYPE="log_sentinel_anomalies"
#    $env:SPLUNK_HEC_VERIFY_SSL="False" # Set to "True" in production with proper certs
# 5. Run the server from your backend directory:
#    uvicorn main:app --host 0.0.0.0 --port 8001 --reload # Running on 8001 to avoid Splunk UI conflict
#
# --- Example Usage (using test_backend.py or Postman/Insomnia): ---
#
# 1. Train Global Semantic Clusters (Run once with a large set of normal logs):
#    POST http://localhost:8001/profile/train-global-clusters
#    Body: (list of LogEntry objects with normal log content)
#
# 2. Learn/Train a profile (send normal logs for specific entities):
#    POST http://localhost:8001/profile/learn
#    Body: (list of LogEntry objects with entity_id, timestamp, log_content)
#
# 3. Detect an anomaly (direct check, stores anomaly in MongoDB AND sends to Splunk HEC):
#    POST http://localhost:8001/detect/anomaly
#    Body: (single LogEntry object)
#    {
#      "entity_id": "user_alice",
#      "timestamp": "2023-10-27T02:00:00",
#      "log_content": "User alice attempted to delete system files rm -rf /etc/passwd"
#    }
#
# 4. Get forensic timeline:
#    GET http://localhost:8001/forensic/timeline/user_alice
#
# 5. Verify in Splunk:
#    Go to Splunk Search & Reporting and search for:
#    index=your_hec_index sourcetype=log_sentinel_anomalies