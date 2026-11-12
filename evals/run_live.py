"""Avalia o prompt contra o modelo real, sem gravar incidentes nem enviar alertas.

Corre o mesmo fluxo de análise da API (LangGraph + Ollama) diretamente, por isso não toca
na base de dados nem no n8n. Uso, dentro do contentor da API (que chega ao Ollama):

    docker cp evals netsentinel-api:/tmp/evals
    docker exec -w /app -e PYTHONPATH=/app netsentinel-api \\
        python /tmp/evals/run_live.py /tmp/evals/incidents.json [--real] [--repeat N]

--real corre só os casos marcados como reais; --repeat repete cada caso N vezes.
"""

import argparse
import json
import sys
import time
from pathlib import Path

from app.agents.graph import threat_graph


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("cases", type=Path)
    parser.add_argument("--real", action="store_true", help="só os casos reais")
    parser.add_argument("--repeat", type=int, default=1)
    args = parser.parse_args()

    cases = json.loads(args.cases.read_text(encoding="utf-8"))
    if args.real:
        cases = [case for case in cases if case.get("real")]

    hits = total = 0
    for case in cases:
        for run in range(1, args.repeat + 1):
            start = time.monotonic()
            result = threat_graph.invoke(
                {
                    "ip_address": case["ip_address"],
                    "threat_type": case["threat_type"],
                    "description": case["description"],
                    "risk_level": "INDETERMINADO",
                    "ai_analysis": "",
                }
            )
            elapsed = time.monotonic() - start
            ok = result["risk_level"] == case["expected"]
            hits += ok
            total += 1
            # Distingue o acerto do modelo do acerto do sistema (modelo + regras de nível mínimo).
            model = result.get("model_risk_level", result["risk_level"])
            source = "ajustado pelas regras" if model != result["risk_level"] else "sem ajuste"
            print(
                f"{'OK ' if ok else 'ERRO'} {case['id']} (#{run}): esperado {case['expected']}, "
                f"saiu {result['risk_level']} (modelo: {model}, {source}) em {elapsed:.0f}s"
            )
            print(f"     parecer: {result['ai_analysis'][:300]}")
            sys.stdout.flush()

    print(f"\n{hits} de {total} corretos")
    return 0 if hits == total else 1


if __name__ == "__main__":
    sys.exit(main())
