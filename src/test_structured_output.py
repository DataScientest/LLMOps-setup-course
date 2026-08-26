# src/test_structured_output.py
import json

import requests


def test_structured_output():
    """Test the structured output functionality with JSON schema."""

    url = "http://localhost:8000/generate"

    # Define a JSON schema for contact information extraction
    contact_schema = {
        "type": "json_schema",
        "json_schema": {
            "name": "contact_extraction",
            "schema": {
                "type": "object",
                "properties": {
                    "nom": {
                        "type": "string",
                        "description": "Le nom complet de la personne",
                    },
                    "email": {
                        "type": "string",
                        "description": "L'adresse email de la personne",
                    },
                    "telephone": {
                        "type": "string",
                        "description": "Le numéro de téléphone de la personne",
                    },
                },
                "required": ["nom", "email", "telephone"],
                "additionalProperties": False,
            },
            "strict": True,
        },
    }

    # Test data
    test_text = "Contactez notre chef de projet Marc Dubois au 06-12-34-56-78 ou marc.dubois@entreprise.com"

    # Create the request payload with structured output
    payload = {
        "prompt": f"Extrais les informations de contact du texte suivant: {test_text}",
        "system_prompt": "Tu es un assistant spécialisé dans l'extraction de données. Extrais uniquement les informations demandées au format JSON spécifié.",
        "model": "groq-qwen-primary",
        "temperature": 0.1,
        "max_tokens": 150,
        "response_format": contact_schema,
    }

    print("=== Test Structured Output ===")
    print(f"Texte d'entrée: {test_text}")
    print(f"Schema utilisé: {json.dumps(contact_schema, indent=2)}")
    print("\nEnvoi de la requête...")

    # Make the API call
    response = requests.post(url, json=payload)

    if response.status_code == 200:
        result = response.json()
        print("\n✅ Succès! Réponse reçue:")
        print(f"Modèle utilisé: {result['model']}")
        print(
            f"Tokens: {result['prompt_tokens']} prompt + {result['completion_tokens']} completion = {result['total_tokens']} total"
        )
        print(f"Coût: {result['cost']}")

        # Parse and display the structured response
        try:
            structured_data = json.loads(result["response"])
            print("\n📋 Données extraites (format structuré):")
            print(json.dumps(structured_data, indent=2, ensure_ascii=False))

            # Validate the structure
            required_fields = ["nom", "email", "telephone"]
            missing_fields = [
                field for field in required_fields if field not in structured_data
            ]

            if not missing_fields:
                print("\n✅ Validation: Tous les champs requis sont présents")
            else:
                print(f"\n❌ Validation: Champs manquants: {missing_fields}")

        except json.JSONDecodeError as e:
            print(f"\n❌ Erreur: La réponse n'est pas un JSON valide: {e}")
            print(f"Réponse brute: {result['response']}")
    else:
        print(f"\n❌ Erreur HTTP {response.status_code}:")
        print(response.text)


def test_without_structured_output():
    """Test the same extraction without structured output for comparison."""

    url = "http://localhost:8000/generate"
    test_text = "Contactez notre chef de projet Marc Dubois au 06-12-34-56-78 ou marc.dubois@entreprise.com"

    payload = {
        "prompt": f"Extrais les informations de contact du texte suivant au format JSON: {test_text}",
        "system_prompt": "Tu es un assistant spécialisé dans l'extraction de données. Réponds uniquement en JSON avec les champs nom, email, telephone.",
        "model": "groq-qwen-primary",
        "temperature": 0.1,
        "max_tokens": 150,
    }

    print("\n\n=== Test Sans Structured Output (pour comparaison) ===")
    print(f"Texte d'entrée: {test_text}")
    print("\nEnvoi de la requête...")

    response = requests.post(url, json=payload)

    if response.status_code == 200:
        result = response.json()
        print("\n✅ Succès! Réponse reçue:")
        print(f"Réponse brute: {result['response']}")

        try:
            structured_data = json.loads(result["response"])
            print("\n📋 Données extraites:")
            print(json.dumps(structured_data, indent=2, ensure_ascii=False))
        except json.JSONDecodeError as e:
            print(f"\n❌ Erreur: La réponse n'est pas un JSON valide: {e}")
    else:
        print(f"\n❌ Erreur HTTP {response.status_code}:")
        print(response.text)


if __name__ == "__main__":
    # Test with structured output
    test_structured_output()

    # Test without structured output for comparison
    test_without_structured_output()
