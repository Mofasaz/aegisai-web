import os
from typing import Any
from openai import AzureOpenAI

class MockResponse:
    def __init__(self, content: str):
        self.content = content

class MockLLM:
    def invoke(self, messages: Any) -> MockResponse:
        # messages is a list of {role, content}; return a deterministic reply
        user = [m for m in messages if m.get("role") == "user"][-1]["content"]
        return MockResponse(f"[MOCK ANSWER] {user}")

class AOAIChatClient:
    """Mimics LangChain's .invoke(messages) interface."""
    def __init__(self):
        self.client = AzureOpenAI(
            api_key=os.getenv("AZURE_OPENAI_API_KEY"),        # <-- your AOAI key
            api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2025-01-01-preview"),
            azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"), # e.g. https://<name>.openai.azure.com/
            timeout=60,
        )
        # In Azure, 'model' is your DEPLOYMENT name (e.g. 'gpt4omini')
        self.deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT")

    def invoke(self, messages, temperature=0.2):
        # messages = [{"role":"system","content":"..."}, {"role":"user","content":"..."}]
        resp = self.client.chat.completions.create(
            model=self.deployment,             # <-- deployment name here
            messages=messages,
            temperature=temperature,
        )
        return resp.choices[0].message  # has .content
        
def get_llm():
    mode = os.getenv("CHAIN_MODE", "azure")
    if mode == "offline":
        return MockLLM()
    else:
        return AOAIChatClient()




