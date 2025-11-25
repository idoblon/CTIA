# dashboard.py
import streamlit as st
import sqlite3
import json
import pandas as pd
from datetime import datetime, timezone
import os
from dotenv import load_dotenv



# Optional: import your existing modules (update names/paths if needed)
# from threat_enrichment import enrich_ioc        # Phase 4
# from scoring import score_ioc_row, update_score_in_db, top_n, score_all_iocs  # Phase 5

load_dotenv()

DB_PATH = "cti.db"
LOGO_PATH = "/core/data/CTI.png"  # provided project image

st.set_page_config(page_title="CTI Dashboard", layout="wide", page_icon="🛡️")

# ---------- Helpers ----------
def get_conn():
    if not os.path.exists(DB_PATH):
        st.error(f"Database not found at {DB_PATH}. Run Phase 3 first.")
        st.stop()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def query_iocs(ioc_type=None, min_score=None, label=None, limit=1000):
    conn = get_conn()
    cur = conn.cursor()
    clauses = []
    params = []
    if ioc_type:
        clauses.append("ioc_type = ?")
        params.append(ioc_type)
    if min_score is not None:
        clauses.append("score >= ?")
        params.append(min_score)
    if label:
        clauses.append("score >= ?")  # label->score mapping
        label_map = {"malicious":75, "suspicious":50, "low":25, "informational":0}
        params[-1] = label_map.get(label, 0) if params else label_map.get(label, 0)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    q = f"SELECT id, ioc_type, value, score, score_updated_at, metadata, source, inserted_at FROM iocs {where} ORDER BY score DESC, score_updated_at DESC LIMIT ?"
    params.append(limit)
    cur.execute(q, tuple(params))
    rows = cur.fetchall()
    conn.close()
    return rows

def row_to_dict(r):
    try:
        meta = json.loads(r["metadata"]) if r["metadata"] else {}
    except Exception:
        meta = {}
    return {
        "id": r["id"],
        "type": r["ioc_type"],
        "value": r["value"],
        "score": r.get("score", 0),
        "score_updated": r.get("score_updated_at"),
        "metadata": meta,
        "source": r.get("source"),
        "inserted_at": r.get("inserted_at")
    }

def export_rows_to_csv(rows, out_path):
    df = pd.DataFrame(rows)
    df.to_csv(out_path, index=False)
    return out_path

# Optional thin wrappers if you have these functions:
def safe_enrich(ioc_value, ioc_type, threat_enrichment=None):
    try:
        if threat_enrichment is not None:
            return threat_enrichment(ioc_value, ioc_type)

        from threat_enrichment import enrich_ioc
        return enrich_ioc(ioc_value, ioc_type)

    except Exception as e:
        return {"error": f"Enrichment unavailable: {e}"}



def safe_score_and_update(ioc_value):
    """
    Call score_ioc_row and update_score_in_db from scoring.py
    Returns new score or error message.
    """
    try:
        from scoring import score_ioc_row, update_score_in_db
        # fetch row from DB
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM iocs WHERE value = ?", (ioc_value,))
        r = cur.fetchone()
        conn.close()
        if not r:
            return {"error": "IOC not found"}
        res = score_ioc_row(r)
        update_score_in_db(res["value"], res["score"], res["score_updated_at"])
        return {"score": res["score"], "label": res["label"]}
    except Exception as e:
        return {"error": str(e)}

# ---------- UI ----------
# Header
col1, col2 = st.columns([1,5])
with col1:
    if os.path.exists(LOGO_PATH):
        st.image(LOGO_PATH, use_column_width=True)
with col2:
    st.title("CTI Dashboard")
    st.caption("Phase 6 — Enrichment, Scoring & Prioritization UI")

# Sidebar filters + actions
st.sidebar.header("Filters")
ioc_type = st.sidebar.selectbox("IOC Type", options=["all","ip","domain","url"], index=0)
min_score = st.sidebar.slider("Min score", min_value=0, max_value=100, value=0, step=1)
search_text = st.sidebar.text_input("Search IOC (substring)")

st.sidebar.markdown("---")
st.sidebar.header("Actions")
selected_action = st.sidebar.selectbox("Action", ["None", "Enrich selected IOC", "Score selected IOC(s)", "Export results to CSV"])
export_name = st.sidebar.text_input("Export filename", value="cti_export.csv")

# Fetch and display
st.header("IOC Table")
rows = query_iocs(ioc_type=None if ioc_type=="all" else ioc_type, min_score=min_score, limit=2000)
# Convert to dicts and optionally filter by search_text
rows_dicts = [row_to_dict(r) for r in rows]
if search_text:
    rows_dicts = [r for r in rows_dicts if search_text.lower() in r["value"].lower()]

# DataFrame view
df_display = pd.DataFrame([{"value": r["value"], "type": r["type"], "score": r["score"], "source": r.get("source"), "updated": r.get("score_updated")} for r in rows_dicts])
st.dataframe(df_display, height=300)

# Select IOC(s)
selected = st.multiselect("Select IOC(s) by value", options=[r["value"] for r in rows_dicts], default=None)

# Action buttons
if selected_action == "Enrich selected IOC":
    if not selected:
        st.warning("Select at least one IOC to enrich.")
    else:
        st.info("Enrichment results (per IOC):")
        for s in selected:
            res = safe_enrich(s, next((r["type"] for r in rows_dicts if r["value"]==s), "ip"))
            st.write(s, res)
            # Optionally save enrichment to metadata:
            if "error" not in res:
                # write metadata into DB
                try:
                    conn = get_conn()
                    cur = conn.cursor()
                    # create minimal metadata: enrichment + sources preserved if present
                    cur.execute("SELECT metadata FROM iocs WHERE value=?", (s,))
                    old = cur.fetchone()
                    old_meta = {}
                    if old and old[0]:
                        try:
                            old_meta = json.loads(old[0])
                        except:
                            old_meta = {}
                    new_meta = old_meta.copy()
                    new_meta["enrichment"] = res
                    cur.execute("UPDATE iocs SET metadata=? WHERE value=?", (json.dumps(new_meta), s))
                    conn.commit()
                    conn.close()
                    st.success(f"Saved enrichment metadata for {s}")
                except Exception as e:
                    st.error(f"Failed to save metadata: {e}")

if selected_action == "Score selected IOC(s)":
    if not selected:
        st.warning("Select at least one IOC to score.")
    else:
        st.info("Scoring results:")
        for s in selected:
            res = safe_score_and_update(s)
            st.write(s, res)

if selected_action == "Export results to CSV":
    if st.button("Export now"):
        # export current rows_dicts
        out_path = export_rows_to_csv(rows_dicts, export_name)
        st.success(f"Exported to {out_path}")
        with open(out_path, "rb") as f:
            st.download_button("Download CSV", data=f, file_name=os.path.basename(out_path))

# Detail pane for a single selected IOC
st.header("IOC Details")
selected_one = st.selectbox("Pick one IOC for details", options=[r["value"] for r in rows_dicts] if rows_dicts else [])
if selected_one:
    item = next((r for r in rows_dicts if r["value"]==selected_one), None)
    if item:
        st.subheader(f"{item['value']}  —  {item['type']}  —  score {item['score']}")
        st.write("Source:", item.get("source"))
        st.write("Inserted:", item.get("inserted_at"))
        st.write("Score updated:", item.get("score_updated"))
        st.markdown("**Metadata / Enrichment**")
        st.json(item.get("metadata") or {})

# Small summary charts
st.header("Summary")
colA, colB = st.columns(2)
with colA:
    df_summary = pd.DataFrame([r for r in rows_dicts])
    if not df_summary.empty:
        type_counts = df_summary["type"].value_counts()
        st.bar_chart(type_counts)
with colB:
    if not df_summary.empty:
        top_scores = df_summary.sort_values("score", ascending=False).head(10)[["value","score"]]
        st.table(top_scores)

st.markdown("---")
st.caption("Streamlit CTI Dashboard — Phase 6")
