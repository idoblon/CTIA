CTIA — Cyber Threat Intelligence Automation


Structure:
- app/: Python package (core, db, utils, dashboard)
- data_feeds/: sample feeds
- .env (api keys)


Run:
1. Create venv and install requirements
python -m venv venv
source venv/bin/activate # or venv\Scripts\activate on Windows
pip install -r requirements.txt


2. Populate .env with API keys (optional)


3. Run initial collection and DB population:
python -m app.main run_all


4. Run Streamlit dashboard:
streamlit run app/dashboard/dashboard.py