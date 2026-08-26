import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional

import mlflow
import openai
import requests
from fastapi import FastAPI, HTTPException
from mlflow.entities.span import SpanType
from mlflow.entities.span_event import SpanEvent
from pydantic import BaseModel, Field

from litellm import completion_cost

logger = logging.getLogger(__name__)

# Get LiteLLM's URL from environment variables, with a default for local dev
LITELLM_URL = os.getenv("LITELLM_URL", "http://litellm:8000")

# Initialize MLflow tracking
mlflow.set_tracking_uri(os.getenv("MLFLOW_TRACKING_URI", "http://mlflow:5000"))

# Configure OpenAI client to point to LiteLLM proxy
client = openai.OpenAI(
    api_key="sk-1234", base_url=LITELLM_URL  # LiteLLM proxy requires any API key
)


def get_default_model():
    """Get the best available model based on priority."""
    logger.debug(f" Getting default model from {LITELLM_URL}")
    try:
        response = requests.get(f"{LITELLM_URL}/models")
        response.raise_for_status()
        available_models = [model["id"] for model in response.json().get("data", [])]

        logger.debug(f" Available models: {available_models}")

        # Priority order: Groq Qwen first, then optional providers
        priority_models = [
            "groq-qwen-primary",
            "gpt-4o-secondary",
            "gemini-third",
            "openrouter-fallback",
        ]

        for model in priority_models:
            if model in available_models:
                logger.debug(f" Selected model: {model}")
                return model

    except Exception as e:
        logger.debug(f" Error getting models: {e}")

    logger.debug(" Using fallback: groq-qwen-primary")
    return "groq-qwen-primary"


# --- Pydantic Models for API requests and responses ---
class PromptRequest(BaseModel):
    prompt: str
    # The default model is our LiteLLM router, which handles the fallback.
    model: str = Field(default_factory=get_default_model)
    temperature: float = 0.7
    max_tokens: int = 150
    # Optional system prompt to set the behavior/role of the AI
    system_prompt: Optional[str] = None
    # Optional response format for structured outputs (JSON schema)
    response_format: Optional[Dict[str, Any]] = None


class PromptResponse(BaseModel):
    response: str
    model: str  # The actual model that was used
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
    lifespan=lifespan,
)


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
        "timestamp": datetime.now(),
    }


# Available models from LiteLLM proxy (fallbacks handled by proxy)
# Models: gpt-4o-primary, gemini-secondary, openrouter-fallback, smart-router
# smart-router has fallbacks: gemini-secondary -> openrouter-fallback


@app.post("/generate", response_model=PromptResponse)
@mlflow.trace(name="llm_generation", span_type=SpanType.LLM)
async def generate_text(prompt_request: PromptRequest):
    """Generate text using LiteLLM with automatic MLflow tracing."""
    logger.debug(f" Starting generate_text with model: {prompt_request.model}")

    # Get the parent span created by the decorator
    parent_span = mlflow.get_current_active_span()
    logger.debug(f" Got parent span: {parent_span}")

    # Create child spans for each step
    with mlflow.start_span("input_processing") as span:
        span.add_event(
            SpanEvent(
                "Processing input request",
                attributes={
                    "model": prompt_request.model,
                    "prompt_preview": prompt_request.prompt[:100],
                },
            )
        )
        span.set_attributes(
            {
                "request.model": prompt_request.model,
                "request.temperature": prompt_request.temperature,
                "request.max_tokens": prompt_request.max_tokens,
                "request.prompt": prompt_request.prompt[:500],  # First 500 chars
                "request.system_prompt": (
                    prompt_request.system_prompt[:500]
                    if prompt_request.system_prompt
                    else None
                ),
                "request.has_system_prompt": bool(prompt_request.system_prompt),
                "request.response_format": (
                    str(prompt_request.response_format)
                    if prompt_request.response_format
                    else None
                ),
                "request.has_response_format": bool(prompt_request.response_format),
            }
        )

    try:
        # Use direct HTTP requests to LiteLLM proxy to avoid client compatibility issues
        with mlflow.start_span("llm_call") as span:
            # Build messages array - include system prompt if provided
            messages = []
            if prompt_request.system_prompt:
                messages.append(
                    {"role": "system", "content": prompt_request.system_prompt}
                )
            messages.append({"role": "user", "content": prompt_request.prompt})
            logger.debug(
                f" About to send request to LiteLLM with model: {prompt_request.model}"
            )
            span.add_event(
                SpanEvent(
                    "Sending request to LiteLLM proxy",
                    attributes={
                        "model": prompt_request.model,
                        "has_system_prompt": bool(prompt_request.system_prompt),
                        "has_response_format": bool(prompt_request.response_format),
                    },
                )
            )
            request_payload = {
                "model": prompt_request.model,
                "messages": messages,
                "temperature": prompt_request.temperature,
                "max_tokens": prompt_request.max_tokens,
            }
            # Add response_format if provided (for structured outputs)
            if prompt_request.response_format:
                request_payload["response_format"] = prompt_request.response_format
            logger.debug(
                "Sending request to model=%s with max_tokens=%s",
                prompt_request.model,
                prompt_request.max_tokens,
            )
            litellm_response = requests.post(
                f"{LITELLM_URL}/chat/completions",
                headers={
                    "Content-Type": "application/json",
                    # LiteLLM accepts a placeholder key when auth is disabled.
                    "Authorization": "Bearer sk-1234",
                },
                json=request_payload,
                timeout=90,
            )
            logger.debug(f" LiteLLM response status: {litellm_response.status_code}")
            logger.debug(f" LiteLLM response headers: {dict(litellm_response.headers)}")

            litellm_response.raise_for_status()
            response_data = litellm_response.json()
            logger.debug("Parsed a successful LiteLLM response")

            span.add_event(SpanEvent("Received response from LiteLLM proxy"))

        with mlflow.start_span("output_processing") as span:
            span.add_event(SpanEvent("Processing LLM response"))
            # Extract details from the successful response
            completion_text = response_data["choices"][0]["message"]["content"]
            usage = response_data["usage"]
            actual_model = response_data["model"] or prompt_request.model

            # Cost calculation is handled by LiteLLM, using the documented method
            try:
                logger.debug(f" Calculating cost for model: {actual_model}")
                cost = (
                    completion_cost(
                        model=actual_model,
                        prompt=prompt_request.prompt,
                        completion=completion_text,
                    )
                    or 0.0
                )
                logger.debug(f" Cost calculated successfully: {cost}")
            except Exception as e:
                logger.debug(f" Error calculating cost: {e}")
                cost = 0.0
            span.add_event(SpanEvent("Calculated cost", attributes={"cost": cost}))

            # Set attributes on the output processing span
            span.set_attributes(
                {
                    "response.model": actual_model,
                    "response.completion_tokens": usage["completion_tokens"],
                    "response.prompt_tokens": usage["prompt_tokens"],
                    "response.total_tokens": usage["total_tokens"],
                    "response.cost": cost,
                    "response.completion_text": completion_text[
                        :500
                    ],  # First 500 chars
                }
            )

            # Also add cost to the main parent span for easy visibility
            if parent_span:
                parent_span.set_attribute("response.cost", cost)

        return PromptResponse(
            response=completion_text,
            model=actual_model,
            prompt_tokens=usage["prompt_tokens"],
            completion_tokens=usage["completion_tokens"],
            total_tokens=usage["total_tokens"],
            cost=cost,
        )

    except Exception as e:
        raise HTTPException(status_code=503, detail=f"LLM request failed: {str(e)}")


@app.get("/models", response_model=ModelsResponse)
async def list_models():
    """List all available models from the LiteLLM router."""
    try:
        response = requests.get(f"{LITELLM_URL}/models")
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Error fetching models: {e}")
