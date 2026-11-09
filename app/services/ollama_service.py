import httpx
import ollama

from app.config import settings


class LLMUnavailableError(Exception):
    """O modelo de IA não respondeu."""


def generate_analysis(messages: list[dict]) -> str:
    """Envia as mensagens ao Ollama e devolve o texto JSON da resposta.

    As mensagens (instruções, exemplos e incidente) vêm de app/agents/prompt.py.
    """
    client = ollama.Client(host=settings.OLLAMA_URL, timeout=settings.OLLAMA_TIMEOUT_SECONDS)
    try:
        response = client.chat(
            model=settings.OLLAMA_MODEL,
            messages=messages,
            format="json",
            options={"temperature": 0.1},
        )
    except (httpx.HTTPError, ollama.ResponseError) as exc:
        raise LLMUnavailableError(str(exc)) from exc
    return response["message"]["content"]
