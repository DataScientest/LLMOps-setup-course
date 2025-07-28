from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import requests
import os
from datetime import datetime
from typing import List

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

# --- FastAPI Application Setup ---
app = FastAPI(
    title="LLMOps API",
    description="API for interacting with LLMs via LiteLLM's smart router."
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

@app.post("/generate", response_model=PromptResponse)
async def generate_text(request: PromptRequest):
    """Generate text by sending a prompt to the LiteLLM router."""
    payload = {
        "model": request.model,
        "messages": [{"role": "user", "content": request.prompt}],
        "temperature": request.temperature,
        "max_tokens": request.max_tokens
    }

    try:
        # A single call to LiteLLM. It handles fallback and tracing.
        response = requests.post(
            f"{LITELLM_URL}/chat/completions",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=45  # Increased timeout for multiple potential calls
        )
        response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)

        data = response.json()
        
        # Extract details from the successful response
        completion = data["choices"][0]["message"]["content"]
        usage = data.get("usage", {})
        actual_model = data.get("model", request.model)
        cost = data.get("cost", 0.0)

        return PromptResponse(
            response=completion,
            model=actual_model,
            prompt_tokens=usage.get("prompt_tokens", 0),
            completion_tokens=usage.get("completion_tokens", 0),
            total_tokens=usage.get("total_tokens", 0),
            cost=cost
        )

    except requests.exceptions.RequestException as e:
        # This will catch connection errors, timeouts, and bad status codes.
        raise HTTPException(status_code=503, detail=f"Failed to communicate with LLM service: {e}")

@app.get("/models", response_model=ModelsResponse)
async def list_models():
    """List all available models from the LiteLLM router."""
    try:
        response = requests.get(f"{LITELLM_URL}/models")
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Error fetching models: {e}")
