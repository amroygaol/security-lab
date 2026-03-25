import requests

PROMETHEUS_URL = "http://localhost:9090"
OLLAMA_URL = "http://localhost:11434/api/generate"


def get_metric(metric):

    url = f"{PROMETHEUS_URL}/api/v1/query"

    r = requests.get(url, params={"query": metric})

    data = r.json()

    if data["data"]["result"]:
        return data["data"]["result"][0]["value"][1]

    return "0"


def ask_ai(metric_value):

    prompt = f"""
You are a cybersecurity analyst.

Total certificates in DigiCert: {metric_value}

Explain what this means for security operations.
"""

    response = requests.post(
        OLLAMA_URL,
        json={
            "model": "llama3.2:3b",
            "prompt": prompt,
            "stream": False
        }
    )

    return response.json()["response"]


metric_value = get_metric("digicert_certificates_total")

print("Metric value:", metric_value)

analysis = ask_ai(metric_value)

print("\nAI Analysis:\n")
print(analysis)