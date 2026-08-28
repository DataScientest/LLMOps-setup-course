"""Minimal direct Gemini completion using the API key from `.env`."""

import os

import requests
from dotenv import load_dotenv


load_dotenv()


def generate_with_gemini(prompt: str, model: str = "gemini-2.5-flash") -> str:
    """Generate a text response with the Gemini REST API."""
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is not set in .env")

    response = requests.post(
        f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        headers={"x-goog-api-key": api_key, "Content-Type": "application/json"},
        json={"contents": [{"parts": [{"text": prompt}]}]},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["candidates"][0]["content"]["parts"][0]["text"]


if __name__ == "__main__":
    print(generate_with_gemini("Explain quantum computing in simple terms."))
