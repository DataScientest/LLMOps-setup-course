FROM ghcr.io/berriai/litellm@sha256:3425d9d76327eda5423c419af9bd37c1fbc94014bf980c7b6a15e78a69ced58e

RUN uv pip install --system --no-cache \
    "mlflow==3.15.1" \
    "qdrant-client==1.15.1"

# Copy any additional config if needed
WORKDIR /app
