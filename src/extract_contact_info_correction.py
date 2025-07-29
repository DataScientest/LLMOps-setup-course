# src/extract_contact_info_correction.py
import requests
import json

def extract_contact_info(text):
    """Extract contact information using the local LLM API."""
    
    url = "http://localhost:8000/generate"
    
    # Define system prompt for role specification
    system_prompt = "Tu es un assistant spécialisé dans l'extraction précise de données. Extrais uniquement les informations demandées au format JSON spécifié. Ne fais aucun commentaire."
    
    # Create few-shot examples in the prompt
    prompt = f"""Extrais le nom, l'email et le numéro de téléphone du texte suivant et retourne-les au format JSON.

Exemples:
"Veuillez contacter Jean Martin à jean.martin@example.com ou au 01-23-45-67-89" → {{"nom": "Jean Martin", "email": "jean.martin@example.com", "telephone": "01-23-45-67-89"}}
"Pour plus d'informations: Sophie Durand (sophie@company.fr, 07-11-22-33-44)" → {{"nom": "Sophie Durand", "email": "sophie@company.fr", "telephone": "07-11-22-33-44"}}
"Notre représentant Pierre Blanc (p.blanc@corp.com) est joignable au 06-99-88-77-66" → {{"nom": "Pierre Blanc", "email": "p.blanc@corp.com", "telephone": "06-99-88-77-66"}}

Maintenant:
"{text}" → """
    
    # Set parameters - low temperature for deterministic extraction
    payload = {
        "prompt": prompt,
        "system_prompt": system_prompt,
        "model": "groq-kimi-primary",
        "temperature": 0.1,  # Low temperature for consistent data extraction
        "max_tokens": 150
    }
    
    # Make the API call
    response = requests.post(url, json=payload)
    response_data = response.json()
    
    # Parse the response string as JSON
    try:
        extracted_info = json.loads(response_data['response'])
        return extracted_info
    except json.JSONDecodeError:
        # Return a structured error if parsing fails
        return {"error": "Failed to parse response as JSON", "raw_response": response_data['response']}

if __name__ == "__main__":
    # Test with example text
    test_text = "Contactez notre chef de projet Marc Dubois au 06-12-34-56-78 ou marc.dubois@entreprise.com"
    result = extract_contact_info(test_text)
    
    print("Texte d'entrée:", test_text)
    print("\nRésultat de l'extraction:")
    print(json.dumps(result, indent=2))
    
    # Expected output:
    # {"nom": "Marc Dubois", "email": "marc.dubois@entreprise.com", "telephone": "06-12-34-56-78"}