"""
build_mitre_index.py - Member B (NLP & Risk)
Embeds MITRE ATT&CK technique descriptions and caches them for fast semantic cosine lookup.
"""
import os
import csv
import json

def main():
    print("[*] Loading MITRE techniques from data/mitre/techniques.csv...")
    csv_path = "data/mitre/techniques.csv"
    if not os.path.exists(csv_path):
        print(f"[!] Error: {csv_path} not found.")
        return

    techniques = []
    with open(csv_path, mode='r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            techniques.append(row)

    print(f"[*] Found {len(techniques)} MITRE techniques.")

    # In production environments with sentence-transformers installed:
    try:
        from sentence_transformers import SentenceTransformer
        print("[*] Loading all-MiniLM-L6-v2 model...")
        model = SentenceTransformer('all-MiniLM-L6-v2')
        texts = [f"{t['name']}: {t['description']}" for t in techniques]
        embeddings = model.encode(texts)
        import joblib
        os.makedirs("models", exist_ok=True)
        joblib.dump({'techniques': techniques, 'embeddings': embeddings}, "models/mitre_index.joblib")
        print("[+] Semantic embeddings cached to models/mitre_index.joblib")
    except ImportError:
        print("[!] Note: sentence-transformers not installed. Building fallback token index...")
        os.makedirs("data/processed", exist_ok=True)
        with open("data/processed/mitre_index.json", "w") as f:
            json.dump(techniques, f, indent=2)
        print("[+] Technique dictionary saved to data/processed/mitre_index.json")

if __name__ == "__main__":
    main()
