import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, classification_report, precision_score, recall_score

DATA_PATH = "data/normalized_emails.csv"

if __name__ == "__main__":
    df = pd.read_csv(DATA_PATH, low_memory=False)

    # Clean + standardize labels
    df["label"] = df["label"].astype(str).str.strip().str.lower()
    df = df[df["label"].isin(["phishing", "legitimate"])].copy()

    # Use raw_text (subject+body) as input
    X = df["raw_text"].astype(str).fillna("")
    y = df["label"]

    # Train/test split with stratification
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # TF-IDF features
    vectorizer = TfidfVectorizer(
        lowercase=True,
        stop_words="english",
        max_features=50000,
        ngram_range=(1, 2),
        min_df=2
    )

    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    # Logistic Regression baseline
    clf = LogisticRegression(max_iter=2000, n_jobs=-1)
    clf.fit(X_train_vec, y_train)

    y_pred = clf.predict(X_test_vec)

    print("=== BASELINE: TF-IDF + Logistic Regression ===")
    print("Test size:", len(y_test))
    print("\n=== CONFUSION MATRIX (labels: phishing, legitimate) ===")
    print(confusion_matrix(y_test, y_pred, labels=["phishing", "legitimate"]))

    print("\n=== PRECISION / RECALL (phishing as positive) ===")
    prec = precision_score(y_test, y_pred, pos_label="phishing")
    rec = recall_score(y_test, y_pred, pos_label="phishing")
    print("Precision:", round(prec, 4))
    print("Recall   :", round(rec, 4))

    print("\n=== CLASSIFICATION REPORT ===")
    print(classification_report(y_test, y_pred))