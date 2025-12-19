import pandas as pd
from agents.unified_agent import run_unified_agent
from agents.url_agent import extract_urls_from_text
from agents.explanation_agent import run_explanation_agent
from orchestrator import combine_agents

df = pd.read_csv(
    "data/normalized_emails.csv",
    dtype=str,
    low_memory=False,
    encoding_errors="ignore"
).fillna("")

row = df.sample(1).iloc[0]

subject = row["subject"]
body = row["body"]
headers_text = row.get("headers_text", "")

urls = extract_urls_from_text(body)

unified = run_unified_agent(subject, body, urls, headers_text)
final = combine_agents(
    unified["text"], unified["url"], unified["metadata"]
)

print("SUBJECT:", subject)
print("\nVERDICT:", final["verdict"], "score:", final["score"])
print("\nEXPLANATION:")
print(run_explanation_agent(final))
