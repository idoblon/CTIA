# dashboard_enhanced.py
import streamlit as st
import sqlite3
import json
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timezone, timedelta
import os
from dotenv import load_dotenv

load_dotenv()

DB_PATH = "db/cti.db"

st.set_page_config(page_title="CTIA Dashboard", layout="wide", page_icon="🛡️")

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 1rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 10px;
        color: white;
        text-align: center;
    }
    .threat-high {
        background-color: #ff6b6b;
        color: white;
        padding: 0.5rem;
        border-radius: 5px;
        font-weight: bold;
    }
    .threat-medium {
        background-color: #ffa500;
        color: white;
        padding: 0.5rem;
        border-radius: 5px;
        font-weight: bold;
    }
    .threat-low {
        background-color: #4caf50;
        color: white;
        padding: 0.5rem;
        border-radius: 5px;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# ---------- Helpers ----------
def get_conn():
    if not os.path.exists(DB_PATH):
        st.error(f"Database not found at {DB_PATH}. Run Phase 3 first.")
        st.stop()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_statistics():
    """Get comprehensive database statistics."""
    conn = get_conn()
    cur = conn.cursor()
    
    stats = {}
    
    # Total IOCs
    cur.execute("SELECT COUNT(*) as total FROM iocs")
    stats['total'] = cur.fetchone()['total']
    
    # By type
    cur.execute("SELECT ioc_type, COUNT(*) as count FROM iocs GROUP BY ioc_type")
    stats['by_type'] = {row['ioc_type']: row['count'] for row in cur.fetchall()}
    
    # By score range
    cur.execute("""
        SELECT 
            CASE 
                WHEN score >= 75 THEN 'Malicious'
                WHEN score >= 50 THEN 'Suspicious'
                WHEN score >= 25 THEN 'Low'
                ELSE 'Informational'
            END as label,
            COUNT(*) as count
        FROM iocs
        GROUP BY label
    """)
    stats['by_label'] = {row['label']: row['count'] for row in cur.fetchall()}
    
    # Enriched count
    cur.execute("SELECT COUNT(*) as enriched FROM iocs WHERE metadata IS NOT NULL AND metadata != '{}'")
    stats['enriched'] = cur.fetchone()['enriched']
    
    # Recent IOCs (last 7 days)
    seven_days_ago = (datetime.now() - timedelta(days=7)).isoformat()
    cur.execute("SELECT COUNT(*) as recent FROM iocs WHERE inserted_at >= ?", (seven_days_ago,))
    stats['recent'] = cur.fetchone()['recent']
    
    conn.close()
    return stats

def query_iocs(ioc_type=None, min_score=None, search_text=None, limit=1000):
    """Query IOCs with filters."""
    conn = get_conn()
    cur = conn.cursor()
    clauses = []
    params = []
    
    if ioc_type and ioc_type != "all":
        clauses.append("ioc_type = ?")
        params.append(ioc_type)
    
    if min_score is not None:
        clauses.append("score >= ?")
        params.append(min_score)
    
    if search_text:
        clauses.append("value LIKE ?")
        params.append(f"%{search_text}%")
    
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    query = f"""
        SELECT id, ioc_type, value, score, score_updated_at, metadata, source, inserted_at 
        FROM iocs {where} 
        ORDER BY score DESC, score_updated_at DESC 
        LIMIT ?
    """
    params.append(limit)
    
    cur.execute(query, tuple(params))
    rows = cur.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]

def get_score_distribution():
    """Get score distribution for histogram."""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT score FROM iocs WHERE score > 0")
    scores = [row['score'] for row in cur.fetchall()]
    conn.close()
    return scores

def get_top_threats(limit=10):
    """Get top threats by score."""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT value, ioc_type, score, source 
        FROM iocs 
        WHERE score > 0 
        ORDER BY score DESC 
        LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_threat_label(score):
    """Get threat label based on score."""
    if score >= 75:
        return "Malicious", "#ff6b6b"
    elif score >= 50:
        return "Suspicious", "#ffa500"
    elif score >= 25:
        return "Low", "#ffeb3b"
    else:
        return "Informational", "#4caf50"

# ---------- UI ----------
# Header
st.markdown('<div class="main-header">🛡️ CTIA Threat Intelligence Dashboard</div>', unsafe_allow_html=True)
st.markdown("---")

# Get statistics
stats = get_statistics()

# Metrics Row
col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.metric("Total IOCs", f"{stats['total']:,}")

with col2:
    st.metric("Enriched", f"{stats['enriched']:,}")

with col3:
    malicious_count = stats['by_label'].get('Malicious', 0)
    st.metric("Malicious", f"{malicious_count:,}", delta=None, delta_color="inverse")

with col4:
    suspicious_count = stats['by_label'].get('Suspicious', 0)
    st.metric("Suspicious", f"{suspicious_count:,}")

with col5:
    st.metric("Recent (7d)", f"{stats['recent']:,}")

st.markdown("---")

# Main Content Area
tab1, tab2, tab3, tab4 = st.tabs(["📊 Overview", "🔍 IOC Explorer", "⚠️ Top Threats", "📈 Analytics"])

# TAB 1: Overview
with tab1:
    col_left, col_right = st.columns(2)
    
    with col_left:
        st.subheader("IOC Type Distribution")
        
        # Pie chart for IOC types
        if stats['by_type']:
            fig_type = px.pie(
                values=list(stats['by_type'].values()),
                names=list(stats['by_type'].keys()),
                title="Distribution by IOC Type",
                color_discrete_sequence=px.colors.qualitative.Set3
            )
            fig_type.update_traces(textposition='inside', textinfo='percent+label')
            st.plotly_chart(fig_type, use_container_width=True)
    
    with col_right:
        st.subheader("Threat Level Distribution")
        
        # Bar chart for threat labels
        if stats['by_label']:
            labels = list(stats['by_label'].keys())
            counts = list(stats['by_label'].values())
            
            colors = {
                'Malicious': '#ff6b6b',
                'Suspicious': '#ffa500',
                'Low': '#ffeb3b',
                'Informational': '#4caf50'
            }
            
            fig_label = go.Figure(data=[
                go.Bar(
                    x=labels,
                    y=counts,
                    marker_color=[colors.get(l, '#cccccc') for l in labels],
                    text=counts,
                    textposition='auto',
                )
            ])
            fig_label.update_layout(
                title="IOCs by Threat Level",
                xaxis_title="Threat Level",
                yaxis_title="Count",
                showlegend=False
            )
            st.plotly_chart(fig_label, use_container_width=True)
    
    # Score Distribution Histogram
    st.subheader("Score Distribution")
    scores = get_score_distribution()
    
    if scores:
        fig_hist = px.histogram(
            scores,
            nbins=20,
            title="Threat Score Distribution",
            labels={'value': 'Score', 'count': 'Number of IOCs'},
            color_discrete_sequence=['#667eea']
        )
        fig_hist.update_layout(
            xaxis_title="Threat Score",
            yaxis_title="Number of IOCs",
            showlegend=False
        )
        st.plotly_chart(fig_hist, use_container_width=True)

# TAB 2: IOC Explorer
with tab2:
    st.subheader("🔍 Search and Filter IOCs")
    
    # Filters
    col_f1, col_f2, col_f3 = st.columns(3)
    
    with col_f1:
        ioc_type = st.selectbox("IOC Type", options=["all", "ip", "domain", "url", "hash"], index=0)
    
    with col_f2:
        min_score = st.slider("Minimum Score", min_value=0, max_value=100, value=0, step=5)
    
    with col_f3:
        search_text = st.text_input("Search IOC (substring)")
    
    # Query IOCs
    iocs = query_iocs(
        ioc_type=ioc_type if ioc_type != "all" else None,
        min_score=min_score,
        search_text=search_text if search_text else None,
        limit=500
    )
    
    st.info(f"Found {len(iocs)} IOCs matching your criteria")
    
    # Display table
    if iocs:
        df_display = pd.DataFrame([
            {
                "Value": ioc['value'][:60] + "..." if len(ioc['value']) > 60 else ioc['value'],
                "Type": ioc['ioc_type'].upper(),
                "Score": ioc['score'],
                "Label": get_threat_label(ioc['score'])[0],
                "Source": ioc.get('source', 'Unknown')[:30],
                "Inserted": ioc.get('inserted_at', '')[:10]
            }
            for ioc in iocs
        ])
        
        st.dataframe(
            df_display,
            use_container_width=True,
            height=400
        )
        
        # IOC Details
        st.subheader("IOC Details")
        selected_value = st.selectbox(
            "Select an IOC to view details",
            options=[ioc['value'] for ioc in iocs],
            index=0 if iocs else None
        )
        
        if selected_value:
            selected_ioc = next((ioc for ioc in iocs if ioc['value'] == selected_value), None)
            
            if selected_ioc:
                col_d1, col_d2 = st.columns(2)
                
                with col_d1:
                    st.write("**Value:**", selected_ioc['value'])
                    st.write("**Type:**", selected_ioc['ioc_type'].upper())
                    st.write("**Score:**", selected_ioc['score'])
                    
                    label, color = get_threat_label(selected_ioc['score'])
                    st.markdown(f'<div style="background-color:{color};color:white;padding:10px;border-radius:5px;text-align:center;font-weight:bold;">{label}</div>', unsafe_allow_html=True)
                
                with col_d2:
                    st.write("**Source:**", selected_ioc.get('source', 'Unknown'))
                    st.write("**Inserted:**", selected_ioc.get('inserted_at', 'Unknown'))
                    st.write("**Last Scored:**", selected_ioc.get('score_updated_at', 'Not scored'))
                
                # Metadata
                st.write("**Enrichment Metadata:**")
                metadata = selected_ioc.get('metadata')
                if metadata:
                    try:
                        meta_dict = json.loads(metadata) if isinstance(metadata, str) else metadata
                        st.json(meta_dict)
                    except:
                        st.write("No enrichment data available")
                else:
                    st.write("No enrichment data available")

# TAB 3: Top Threats
with tab3:
    st.subheader("⚠️ Top Threats by Score")
    
    top_count = st.slider("Number of threats to display", min_value=10, max_value=100, value=20, step=10)
    
    top_threats = get_top_threats(limit=top_count)
    
    if top_threats:
        # Create a formatted table
        for i, threat in enumerate(top_threats, 1):
            label, color = get_threat_label(threat['score'])
            
            col_t1, col_t2, col_t3, col_t4 = st.columns([1, 5, 2, 2])
            
            with col_t1:
                st.write(f"**#{i}**")
            
            with col_t2:
                st.write(f"`{threat['value'][:50]}`")
            
            with col_t3:
                st.markdown(f'<div style="background-color:{color};color:white;padding:5px;border-radius:5px;text-align:center;">{threat["score"]}</div>', unsafe_allow_html=True)
            
            with col_t4:
                st.write(threat['ioc_type'].upper())
            
            st.markdown("---")
    else:
        st.info("No threats found in database")

# TAB 4: Analytics
with tab4:
    st.subheader("📈 Threat Intelligence Analytics")
    
    # Timeline analysis (if we had timestamp data)
    st.write("**Database Statistics**")
    
    col_a1, col_a2 = st.columns(2)
    
    with col_a1:
        st.metric("Total IOCs", f"{stats['total']:,}")
        st.metric("Enrichment Rate", f"{(stats['enriched']/stats['total']*100):.1f}%" if stats['total'] > 0 else "0%")
    
    with col_a2:
        st.metric("High Severity (≥75)", f"{stats['by_label'].get('Malicious', 0):,}")
        st.metric("Medium Severity (50-74)", f"{stats['by_label'].get('Suspicious', 0):,}")
    
    # Type breakdown table
    st.write("**IOC Type Breakdown**")
    type_df = pd.DataFrame([
        {"Type": k.upper(), "Count": v, "Percentage": f"{(v/stats['total']*100):.1f}%"}
        for k, v in stats['by_type'].items()
    ])
    st.dataframe(type_df, use_container_width=True)

# Sidebar
st.sidebar.header("⚙️ Actions")

if st.sidebar.button("🔄 Refresh Data"):
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.header("📥 Export")

export_format = st.sidebar.selectbox("Export Format", ["CSV", "JSON"])

if st.sidebar.button("Export Current View"):
    iocs = query_iocs(limit=10000)
    
    if export_format == "CSV":
        df_export = pd.DataFrame(iocs)
        csv = df_export.to_csv(index=False)
        st.sidebar.download_button(
            label="Download CSV",
            data=csv,
            file_name=f"ctia_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
    else:
        json_str = json.dumps(iocs, indent=2)
        st.sidebar.download_button(
            label="Download JSON",
            data=json_str,
            file_name=f"ctia_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )

st.sidebar.markdown("---")
st.sidebar.info("""
**CTIA Dashboard**  
Cyber Threat Intelligence Automation  

**Features:**
- 📊 Real-time statistics
- 🔍 Advanced filtering
- ⚠️ Threat prioritization
- 📈 Visual analytics
- 📥 Data export

**Phase 9 Complete** ✅
""")

# Footer
st.markdown("---")
st.caption("CTIA Dashboard v2.0 - Enhanced Visualization | Phase 9 Complete")
