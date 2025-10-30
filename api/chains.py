import os
from typing import Any

class MockResponse:
    def __init__(self, content: str):
        self.content = content

class MockLLM:
    def invoke(self, messages: Any) -> MockResponse:
        # messages is a list of {role, content}; return a deterministic reply
        user = [m for m in messages if m.get("role") == "user"][-1]["content"]
        return MockResponse(f"[MOCK ANSWER] {user}")

def get_llm():
    mode = os.getenv("CHAIN_MODE", "azure")
    if mode == "offline":
        return MockLLM()
    else:
        from langchain_openai import AzureChatOpenAI
        return AzureChatOpenAI(
            azure_deployment=os.getenv("AZURE_OPENAI_DEPLOYMENT"),
            azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
            api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-06-01"),
            temperature=0.2,
        )


