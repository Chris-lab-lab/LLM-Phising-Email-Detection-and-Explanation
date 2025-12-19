import pandas as pd

from agents.unified_agent import run_unified_agent
from agents.url_agent import extract_urls_from_text
from orchestrator import combine_agents

# -------------------------------------------------
# Config
# -------------------------------------------------

DATA_PATH = "data/normalized_emails.csv"

N_PHISH = 10
N_LEGIT = 10

# -------------------------------------------------
# Single-row runner
# -------------------------------------------------

def run_one(row):
    subject = str(row.get("subject", ""))
    body = str(row.get("body", ""))
    headers_text = str(row.get("headers_text", ""))

    urls = extract_urls_from_text(body)

    unified = run_unified_agent(
        subject=subject,
        body=body,
        urls=urls,
        headers_text=headers_text,
    )

    final = combine_agents(
        unified["text"],
        unified["url"],
        unified["metadata"],
    )

    return final["verdict"]

# -------------------------------------------------
# Main evaluation
# -------------------------------------------------

if __name__ == "__main__":
    df = pd.read_csv(
        DATA_PATH,
        dtype=str,
        low_memory=False,
        encoding_errors="ignore",
    ).fillna("")

    df["label"] = df["label"].str.strip().str.lower()

    print("LABEL COUNTS:")
    print(df["label"].value_counts().head(10))

    phish_pool = df[df["label"] == "phishing"]
    legit_pool = df[df["label"] == "legitimate"]

    if len(phish_pool) == 0 or len(legit_pool) == 0:
        raise RuntimeError("Not enough labeled data to evaluate.")

    df_phish = phish_pool.sample(min(N_PHISH, len(phish_pool)), random_state=42)
    df_legit = legit_pool.sample(min(N_LEGIT, len(legit_pool)), random_state=42)

    test_df = pd.concat([df_phish, df_legit], ignore_index=True)

    y_true = []
    y_pred = []

    for i, row in test_df.iterrows():
        true_label = row["label"]
        pred = run_one(row)

        y_true.append(true_label)
        y_pred.append(pred)

        print(f"[{i+1}/{len(test_df)}] true={true_label} pred={pred}")

    # -------------------------------------------------
    # Confusion matrix
    # -------------------------------------------------

    labels = ["phishing", "legitimate", "unsure"]

    cm = pd.crosstab(
        pd.Series(y_true, name="true"),
        pd.Series(y_pred, name="pred"),
        dropna=False,
    )

    for col in labels:
        if col not in cm.columns:
            cm[col] = 0
    cm = cm[labels]

    for row_label in ["phishing", "legitimate"]:
        if row_label not in cm.index:
            cm.loc[row_label] = [0, 0, 0]

    print("\n=== CONFUSION MATRIX ===")
    print(cm)

    # -------------------------------------------------
    # Metrics (phishing = positive, unsure = negative)
    # -------------------------------------------------

    TP = cm.loc["phishing", "phishing"]
    FN = cm.loc["phishing", "legitimate"] + cm.loc["phishing", "unsure"]
    FP = cm.loc["legitimate", "phishing"]
    TN = cm.loc["legitimate", "legitimate"] + cm.loc["legitimate", "unsure"]

    precision = TP / (TP + FP) if (TP + FP) else 0.0
    recall = TP / (TP + FN) if (TP + FN) else 0.0

    print("\n=== METRICS (phishing as positive) ===")
    print("Precision:", round(precision, 3))
    print("Recall   :", round(recall, 3))
