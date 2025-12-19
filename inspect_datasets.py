import pandas as pd

DATASETS = {
    "emails": "data/emails.csv",
    "nazario_5": "data/Nazario_5.csv",
    "phishing_email": "data/Phishing_Email.csv",
}

for name, path in DATASETS.items():
    print("\n" + "=" * 60)
    print(f"DATASET: {name}")
    print(f"PATH: {path}")

    try:
        # Read only a few rows, safely
        df = pd.read_csv(
            path,
            dtype=str,
            encoding_errors="ignore",
            low_memory=False,
            nrows=5,
        )

        print("SHAPE (sampled):", df.shape)
        print("COLUMNS:", list(df.columns))
        print("HEAD SAMPLE:")
        print(df.head(2).to_string(index=False))

    except Exception as e:
        print("FAILED:", repr(e))
