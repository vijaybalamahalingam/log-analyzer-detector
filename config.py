import os
from dotenv import load_dotenv

# Load environment variables from .env only once
load_dotenv()

def get_azure_openai_config():
    """Get Azure OpenAI configuration from environment variables."""
    # Get credentials from environment variables
    endpoint = os.getenv('AZURE_OPENAI_ENDPOINT', "https://htcgpt4omodel.openai.azure.com/")
    deployment_name = os.getenv('AZURE_OPENAI_DEPLOYMENT_NAME', "gpt4o16kmodel")
    api_key = os.getenv('AZURE_OPENAI_API_KEY')
    api_version = os.getenv('AZURE_OPENAI_API_VERSION', "2024-07-01-preview")
    
    if not api_key:
        raise ValueError("AZURE_OPENAI_API_KEY environment variable is not set. Please set it in your .env file or environment.")
    
    return {
        'endpoint': endpoint,
        'deployment_name': deployment_name,
        'api_key': api_key,
        'api_version': api_version
    } 