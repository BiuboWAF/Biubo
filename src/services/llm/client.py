import logging
from typing import Union, List, Optional
from openai import OpenAI
from src.config.settings import settings

logger = logging.getLogger("WAF.LLM")

def llm_call(question: Union[str, List[dict]], thinking: bool = False, model: str = None) -> str:
    """Generic OpenAI-compatible LLM interface."""
    if isinstance(question, str):
        question = [{"role": "user", "content": question}]
    
    api_key = settings.API_KEY
    base_url = settings.LLM_BASE_URL
    model = model or settings.LLM_MODEL
    
    if not api_key:
        logger.warning("LLM call skipped: No API_KEY configured.")
        return ""
    
    try:
        client = OpenAI(
            api_key=api_key,
            base_url=base_url,
        )
        completion = client.chat.completions.create(
            model=model,
            messages=question,
            extra_body={"enable_thinking": thinking} if thinking else {},
            stream=True
        )
        answer = ""
        for chunk in completion:
            if hasattr(chunk.choices[0], "delta") and hasattr(chunk.choices[0].delta, "content") and chunk.choices[0].delta.content:
                answer += chunk.choices[0].delta.content
        return answer
    except Exception as e:
        logger.error(f"LLM call failed: {e}")
        return ""