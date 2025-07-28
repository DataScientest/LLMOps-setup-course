from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import requests
import os
import mlflow
import openai

from datetime import datetime
from typing import List, Dict, Any, Optional
from contextlib import asynccontextmanager
from mlflow.entities import SpanType

# Initialize MLflow tracking
mlflow.set_tracking_uri(os.getenv("MLFLOW_TRACKING_URI", "http://mlflow:5000"))

# Configure OpenAI client to point to LiteLLM proxy
client = openai.OpenAI(
    api_key="sk-1234",  # LiteLLM proxy requires any API key
    base_url=os.getenv("LITELLM_URL", "http://litellm:8000")
)

# --- Pydantic Models for API requests and responses ---
class PromptRequest(BaseModel):
    prompt: str
    # The default model is our LiteLLM router, which handles the fallback.
    model: str = "smart-router"
    temperature: float = 0.7
    max_tokens: int = 150

class PromptResponse(BaseModel):
    response: str
    model: str # The actual model that was used
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    cost: float

class ModelInfo(BaseModel):
    id: str
    object: str
    created: int
    owned_by: str

class ModelsResponse(BaseModel):
    object: str
    data: List[ModelInfo]

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage MLflow experiment tracking."""
    # Enable auto-tracing for LiteLLM
    mlflow.litellm.autolog()
    
    # Set the experiment
    mlflow.set_experiment("llmops-new")
    
    yield
    
    # Cleanup resources if needed
    pass

# --- FastAPI Application Setup ---
app = FastAPI(
    title="LLMOps API",
    description="API for interacting with LLMs via LiteLLM's smart router.",
    lifespan=lifespan
)

# Get LiteLLM's URL from environment variables, with a default for local dev
LITELLM_URL = os.getenv("LITELLM_URL", "http://litellm:8000")

# --- API Endpoints ---
@app.get("/")
async def root():
    """Root endpoint providing a welcome message."""
    return {"message": "LLMOps API is running!", "timestamp": datetime.now()}

@app.get("/health")
async def health_check():
    """Health check endpoint to verify service status."""
    return {"status": "healthy", "timestamp": datetime.now()}

@app.get("/debug")
async def debug_config():
    """Debug endpoint to show current configuration."""
    return {
        "litellm_url": os.getenv("LITELLM_URL", "http://litellm:8000"),
        "mlflow_uri": os.getenv("MLFLOW_TRACKING_URI", "http://mlflow:5000"),
        "openai_client_base_url": str(client.base_url),
        "using_litellm_proxy": True,
        "timestamp": datetime.now()
    }

# Available models from LiteLLM proxy (fallbacks handled by proxy)
# Models: gpt-4o-primary, gemini-secondary, openrouter-fallback, smart-router
# smart-router has fallbacks: gemini-secondary -> openrouter-fallback

@app.post("/generate", response_model=PromptResponse)
@mlflow.trace(name="llm_generation", span_type=SpanType.LLM)
async def generate_text(prompt_request: PromptRequest):
    """Generate text using LiteLLM with automatic MLflow tracing."""
    
    # Get current span and add attributes
    span = mlflow.get_current_active_span()
    if span:
        span.set_attributes({
            "request.model": prompt_request.model,
            "request.temperature": prompt_request.temperature,
            "request.max_tokens": prompt_request.max_tokens,
            "request.prompt": prompt_request.prompt[:500]  # First 500 chars
        })
    
    try:
        # Use OpenAI client pointing to LiteLLM proxy - fallbacks are handled by the proxy
        response = client.chat.completions.create(
            model=prompt_request.model,
            messages=[{"role": "user", "content": prompt_request.prompt}],
            temperature=prompt_request.temperature,
            max_tokens=prompt_request.max_tokens
        )
        
        # Extract details from the successful response
        completion = response.choices[0].message.content
        usage = response.usage
        actual_model = response.model or prompt_request.model
        
        # Calculate cost if available (LiteLLM proxy provides this in headers)
        cost = 0.0  # Will be calculated by LiteLLM proxy
        
        # Add response attributes to span
        if span:
            span.set_attributes({
                "response.model": actual_model,
                "response.prompt_tokens": usage.prompt_tokens,
                "response.completion_tokens": usage.completion_tokens,
                "response.total_tokens": usage.total_tokens,
                "response.cost": cost,
                "response.content": completion[:500]  # First 500 chars
            })
        
        return PromptResponse(
            response=completion,
            model=actual_model,
            prompt_tokens=usage.prompt_tokens,
            completion_tokens=usage.completion_tokens,
            total_tokens=usage.total_tokens,
            cost=cost
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=503, 
            detail=f"LLM request failed: {str(e)}"
        )

@app.get("/models", response_model=ModelsResponse)
async def list_models():
    """List all available models from the LiteLLM router."""
    try:
        response = requests.get(f"{LITELLM_URL}/models")
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Error fetching models: {e}")
