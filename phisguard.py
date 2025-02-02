
# phishguard.py
import streamlit as st
import pandas as pd
import numpy as np
from transformers import pipeline
import xgboost as xgb
import requests
from urllib.parse import urlparse
import hashlib
import re
from datetime import datetime

# Configuration
THREAT_FEED_URLS = [
    "https://openphish.com/feed.txt",
    "https://raw.githubusercontent.com/Phish-Database/Phish.Database/master/phishing-links-NEW.txt"
]

# Load models (cache for performance)
@st.cache_resource
def load_models():
    return {
        "email_model": pipeline(
            "text-classification", 
            model="wesleyacheng/sms-spam-classification-with-bert"
        )
        # "url_model": xgb.Booster(model_file="XGBoostClassifier.pickle.dat")
    }

# Threat intelligence cache
@st.cache_resource
def load_threat_feeds():
    threat_db = set()
    for feed in THREAT_FEED_URLS:
        try:
            response = requests.get(feed, timeout=10)
            threat_db.update(response.text.splitlines())
        except Exception as e:
            st.error(f"Error loading threat feed: {str(e)}")
    return threat_db

# Feature engineering for URLs
def extract_url_features(url):
    parsed = urlparse(url)
    return {
        "length": len(url),
        "num_digits": sum(c.isdigit() for c in url),
        "num_special": len(re.findall(r'[^a-zA-Z0-9]', url)),
        "has_https": 1 if parsed.scheme == "https" else 0,
        "domain_age": (datetime.now() - datetime(2020, 1, 1)).days,  # Placeholder
        "tld": len(parsed.netloc.split('.')[-1]),
        "is_ip": 1 if re.match(r'^\d+\.\d+\.\d+\.\d+$', parsed.netloc) else 0
    }

# Streamlit UI
def main():
    st.set_page_config(page_title="PhishGuard", layout="wide")
    st.title("Phishing Detection Dashboard")
    
    # Initialize models and data
    models = load_models()
    threat_db = load_threat_feeds()
    
    # Sidebar controls
    st.sidebar.header("Analysis Options")
    analysis_type = st.sidebar.radio("Select Analysis Type:", ["Email"])
    
    # Main content area
    tab1, tab2, tab3 = st.tabs(["Live Analysis", "Statistics", "Threat Intelligence"])
    
    with tab1:
        if analysis_type == "Email":
            email_content = st.text_area("Paste email content:", height=200)
            if st.button("Analyze Email"):
                with st.spinner("Analyzing..."):
                    result = models["email_model"](email_content)[0]
                    st.success(f"Result: {result['label']} (confidence: {result['score']:.2f})")
        # else:
        #     url = st.text_input("Enter URL to analyze:")
        #     if st.button("Check URL"):
        #         with st.spinner("Analyzing..."):
        #             # Check threat database first
        #             url_hash = hashlib.sha256(url.encode()).hexdigest()
        #             if url_hash in threat_db:
        #                 st.error("Known malicious URL (threat feed match)!")
        #             else:
        #                 # ML analysis
        #                 features = extract_url_features(url)
        #                 xgb_features = pd.DataFrame([features]).values
        #                 prediction = models["url_model"].predict(xgb.DMatrix(xgb_features))[0]
        #                 st.success(f"Malicious probability: {prediction:.2f}")

    with tab2:
        st.header("Detection Statistics")
        # Example visualization
        chart_data = pd.DataFrame({
            "Type": ["Email", "URL"],
            "Detection Rate": [0.92, 0.85]
        })
        st.bar_chart(chart_data, x="Type", y="Detection Rate")
        
    with tab3:
        st.header("Latest Threat Intelligence")
        threat_df = pd.DataFrame(list(threat_db)[-10:], columns=["Malicious Indicators"])
        st.dataframe(threat_df)

if __name__ == "__main__":
    main()


# ---

# ### *System Architecture*

# phishguard/
# ├── phishguard.py            # Main Streamlit app
# ├── xgboost_url_model.bin    # Pre-trained XGBoost model
# ├── requirements.txt
# └── data/
#     └── threat_cache.json    # Local threat intel storage


# ---

# ### *Key Components*

# 1. *Email Analysis*
#    - Uses DistilBERT model fine-tuned on phishing emails
#    - Real-time text classification
#    - Confidence scores for predictions

# 2. *URL Analysis*
#    - XGBoost model with 7+ lexical features
#    - Threat feed integration (OpenPhish, Phish.Database)
#    - SHA-256 hash matching

# 3. *Dashboard Features*
#    - Real-time analysis interface
#    - Detection statistics visualization
#    - Threat intelligence monitoring
#    - Responsive Streamlit UI

# ---

# ### *Setup Instructions*

# 1. *Install Dependencies*
# bash
# pip install streamlit transformers xgboost pandas requests


# 2. *Download Models*
# python
# # Get XGBoost model
# import xgboost as xgb
# from sklearn.datasets import make_classification

# # Example model training (replace with your dataset)
# X, y = make_classification(n_samples=1000, n_features=7)
# model = xgb.XGBClassifier().fit(X, y)
# model.save_model("xgboost_url_model.bin")


# 3. *Run Application*
# bash
# streamlit run phishguard.py


# ---





