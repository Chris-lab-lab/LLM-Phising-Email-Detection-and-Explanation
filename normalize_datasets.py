import pandas as pd
import uuid
import re
from pathlib import Path

# -----------------------------------
# Dataset configuration
# -----------------------------------

DATASETS = [
    ("emails", "data/emails.csv"),
    ("nazario_5", "data/Nazario_5.csv"),
    ("phishing_email", "data/Phishing_Email.csv"),
]

COLUMN_MAPS = {
    "emails": {
        "subject": ["subject", "Subject", "SUBJECT", "title"],
        "body": ["body", "Body", "text", "Text", "content", "message", "Message"],
        "label": ["label", "Label", "class", "Class", "target"],
    },
    "nazario_5": {
        "subject": ["subject", "Subject"],
        "body": ["body", "Body", "text", "Text", "email", "Email", "message"],
        "label": ["label", "Label", "class", "Class", "phishing"],
    },
    "phishing_email": {
        "subject": ["subject", "Subject", "Email Subject"],
        "body": ["body", "Body", "Email Text", "text", "content"],
        "label": ["label", "Label", "Class", "target"],
    },
}

LABEL_MAP = {
    "phishing": "phishing",
    "spam": "phishing",
    "1": "phishing",
    "legitimate": "legitimate",
    "ham": "legitimate",
    "0": "legitimate",
}

# -----------------------------------
# Helpers
# -----------------------------------

def pick_col(columns, candidates):
    for c in candidates:
        if c in columns:
            return c
    return None

def clean_text(x: str) -> str:
    x = "" if x is None else str(x)
    x = x.replace("\r\n", "\n").replace("\r", "\n")
    x = re.sub(r"[ \t]+", " ", x).strip()
    return x

def normalize_chunk(df, dataset_name):
    cmap = COLUMN_MAPS[dataset_name]

    sub_col = pick_col(df.columns, cmap["subject"])
    body_col = pick_col(df.columns, cmap["body"])
    lab_col = pick_col(df.columns, cmap["label"])

    out = pd.DataFrame({
        "id": [str(uuid.uuid4()) for _ in range(len(df))],
        "source_dataset": dataset_name,
        "subject": df[sub_col].map(clean_text) if sub_col else "",
        "body": df[body_col].map(clean_text) if body_col else "",
    })

    if lab_col:
        raw = df[lab_col].fillna("").astype(str).str.strip().str.lower()
        out["label"] = raw.map(lambda v: LABEL_MAP.get(v, ""))
    else:
        out["label"] = ""

    out = out[(out["subject"] != "") | (out["body"] != "")]
    return out

# -----------------------------------
# Main
# -----------------------------------

def main():
    out_path = Path("data/normalized_emails.csv")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if out_path.exists():
        out_path.unlink()

    first_write = True
    chunksize = 50_000  # safe for large files

    for name, path in DATASETS:
        if not Path(path).exists():
            print(f"[SKIP] Missing: {path}")
            continue

        print(f"[READ] {name}: {path}")

        for chunk in pd.read_csv(
            path,
            dtype=str,
            encoding_errors="ignore",
            low_memory=False,
            chunksize=chunksize,
        ):
            norm = normalize_chunk(chunk, name)
            norm.to_csv(
                out_path,
                mode="a",
                index=False,
                header=first_write,
            )
            first_write = False

    print(f"[DONE] Saved normalized dataset → {out_path}")

if __name__ == "__main__":
    main()
