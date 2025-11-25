from threat_feeds import THREAT_FEEDS, fetch_feed
from normalizer import normalize_feed
from database import initialize_database, insert_ioc
import json
import os

RAW_DIR = "raw_feeds"
NORMALIZED_DIR = "normalized_feeds"


def create_directories():
    os.makedirs(RAW_DIR, exist_ok=True)
    os.makedirs(NORMALIZED_DIR, exist_ok=True)


# ---------------- PHASE 1 ---------------- #
def run_phase1():
    print("[*] Collecting raw threat feeds...")

    for name, url in THREAT_FEEDS.items():
        data = fetch_feed(name, url)

        if data:
            filepath = os.path.join(RAW_DIR, f"{name}.txt")
            with open(filepath, "w") as f:
                f.write(data)
            print(f"[+] Saved {filepath}")


# ---------------- PHASE 2 ---------------- #
def run_phase2():
    print("[*] Normalizing feeds...")

    for file in os.listdir(RAW_DIR):
        feed_path = os.path.join(RAW_DIR, file)
        output_path = os.path.join(NORMALIZED_DIR, f"{file.replace('.txt', '')}.json")

        normalized_data = normalize_feed(feed_path)

        with open(output_path, "w") as out:
            json.dump(normalized_data, out, indent=4)

        print(f"[+] Normalized: {output_path} ({len(normalized_data)} IOCs)")


# ---------------- PHASE 3 ---------------- #
def run_phase3():
    print("[*] Inserting normalized IOCs into database...")
    initialize_database()

    for file in os.listdir(NORMALIZED_DIR):
        source_name = file.replace(".json", "")
        file_path = os.path.join(NORMALIZED_DIR, file)

        with open(file_path, "r") as f:
            iocs = json.load(f)

        count = 0
        for item in iocs:
            if insert_ioc(item["type"], item["value"], source_name):
                count += 1

        print(f"[+] Added {count} new IOCs from {source_name}")


def run_all():
    create_directories()
    run_phase1()
    run_phase2()
    run_phase3()


if __name__ == "__main__":
    run_all()
