# LLMOps Setup Course

This repository demonstrates a production-ready LLM application with model fallback, monitoring, and testing.

## Architecture

- **FastAPI Application**: REST API for LLM interactions with cascade fallback
- **LiteLLM Proxy**: Unified interface for multiple LLM providers (OpenAI, Gemini, OpenRouter)
- **MLflow**: Experiment tracking and prompt tracing

## Prerequisites

- Docker and Docker Compose
- API keys for:
  - OpenAI (GPT-4o)
  - Gemini 2.0 Flash
  - OpenRouter (Mistral 7B fallback)

## Quick Start

1. Setup environment:
   ```bash
   cp env.example .env
   # Edit .env with your API keys
   ```

2. Start services:
   ```bash
   docker-compose up -d --build
   ```

3. Access services:
   - API: http://localhost:8000
   - LiteLLM: http://localhost:8001
   - MLflow UI: http://localhost:5000

## API Endpoints

### Text Generation
```http
POST /generate
Content-Type: application/json

{
  "prompt": "Your prompt here",
  "model": "smart-router",  # Uses cascade fallback
  "temperature": 0.7
}
```

### Available Models
```http
GET /models
```

### Health Check
```http
GET /health
```

## Model Fallback Strategy

1. **Primary**: `gpt-4o-primary` (OpenAI GPT-4o)
2. **Secondary**: `gemini-secondary` (Gemini 2.0 Flash)
3. **Fallback**: `openrouter-fallback` (Mistral 7B via OpenRouter)

Use `smart-router` model name to enable automatic fallback.

## Monitoring with MLflow

All LLM calls are tracked with:
- Input/Output parameters
- Token usage and latency
- Success/Failure status
- Full prompt/response history

Access the MLflow UI at `http://localhost:5000`

## Project Structure

```
.
├── docker-compose.yml      # Service definitions
├── litellm-config.yaml    # LiteLLM model configuration
├── .env.example           # Template for environment variables
├── test-requirements.txt  # Testing dependencies
├── tests/                 # Integration tests
├── mlflow-data/           # MLflow experiment data
└── src/
    └── api/               # FastAPI application
        ├── main.py        # API endpoints
        └── Dockerfile     # API container setup
```

## Development

### Running Tests
Tests run inside the container:
```bash
docker-compose exec api pytest /app/tests/
```

### Stopping Services
```bash
docker-compose down
```

### Viewing Logs
```bash
docker-compose logs -f
```

## Data Persistence
- MLflow data: `./mlflow-data`
- Test coverage reports: `./htmlcov`

## Makefile

The Makefile provides a set of commands to manage the environment and run tests. Here are the available commands:

> Note: `jq` is required to parse the API responses.

```sh
# Check API health
make api-test

# List available models
make api-models

# Generate text with fallback model
make api-generate PROMPT="What is the capital of France?"

# Generate text specifically with Gemini
make api-generate-gemini PROMPT="Explain quantum computing in simple terms"
```