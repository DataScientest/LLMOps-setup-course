FROM ghcr.io/berriai/litellm@sha256:3425d9d76327eda5423c419af9bd37c1fbc94014bf980c7b6a15e78a69ced58e

# Install MLflow and Qdrant for integration
RUN pip install mlflow qdrant-client

# Copy any additional config if needed
WORKDIR /app
