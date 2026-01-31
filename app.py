"""
Large-Scale Log Intelligence System - Flask Backend
Loads logs from local logs.tsv (TSV), stats, Gemini LLM analysis, search.
"""

import json
import os
import pandas as pd
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()

app = Flask(__name__)
CORS(app)

# ---------------------------------------------------------------------------
# Global in-memory store for logs
# ---------------------------------------------------------------------------
df = None
LOGS_FILE = 'logs.tsv'

# ---------------------------------------------------------------------------
# Serve the Frontend
# ---------------------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')

# ---------------------------------------------------------------------------
# /upload - PARSER FOR UNIX TIMESTAMP TSV FORMAT
# ---------------------------------------------------------------------------
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    global df
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), LOGS_FILE)
    if not os.path.isfile(path):
        return jsonify({'error': f'File not found: {LOGS_FILE}'}), 404

    try:
        # Define the exact columns based on your snippet
        # Column 0: Host
        # Column 1: Dash (ignored)
        # Column 2: Unix Timestamp
        # Column 3: Method (GET)
        # Column 4: URL
        # Column 5: Status
        # Column 6: Bytes
        column_names = ['host', 'dash', 'time_epoch', 'method', 'url', 'status', 'bytes']

        # Read the file as a strict TSV
        df = pd.read_csv(
            path, 
            sep='\t', 
            header=None, 
            names=column_names, 
            on_bad_lines='skip', 
            encoding='latin1',
            low_memory=False
        )

        # ---------------- DATA TRANSFORMATION ----------------
        
        # 1. Create the 'request' column by combining Method + URL
        # Result: "GET /shuttle/missions/..."
        df['request'] = df['method'].astype(str) + " " + df['url'].astype(str)

        # 2. Convert Unix Timestamp (804571304) to Readable Date
        # Result: Datetime Object
        df['dt'] = pd.to_datetime(df['time_epoch'], unit='s', errors='coerce')
        
        # 3. Create a string version of time for the frontend display
        df['time'] = df['dt'].dt.strftime('%d/%b/%Y:%H:%M:%S')

        # 4. Clean Numeric Columns
        df['status'] = pd.to_numeric(df['status'], errors='coerce').fillna(0).astype(int)
        df['bytes'] = pd.to_numeric(df['bytes'], errors='coerce').fillna(0)

        # 5. Drop helper columns to keep memory usage low
        df = df[['host', 'time', 'request', 'status', 'bytes', 'dt']]

        return jsonify({'message': f'Successfully loaded {len(df)} logs.'})

    except Exception as e:
        print(f"Upload Error: {e}")
        return jsonify({'error': str(e)}), 500

# ---------------------------------------------------------------------------
# /stats
# ---------------------------------------------------------------------------
@app.route('/stats', methods=['GET'])
def stats():
    global df
    if df is None or df.empty:
        return jsonify({
            'total': 0, 'unique_ips': 0, 'error_rate_pct': 0.0,
            'top_5_ips': [], 'top_5_endpoints': [], 'requests_over_time': [],
        })

    total = len(df)
    unique_ips = int(df['host'].nunique())

    # Error rate
    error_count = df[(df['status'] >= 400) & (df['status'] < 600)].shape[0]
    error_rate_pct = round(100.0 * error_count / total, 2) if total else 0.0

    # Top 5 IPs
    top_5_ips = df['host'].value_counts().head(5)
    top_5_ips_list = [{'ip': str(k), 'count': int(v)} for k, v in top_5_ips.items()]

    # Top 5 Endpoints
    try:
        top_5_endpoints = df['request'].str.split().str[1].value_counts().head(5)
    except:
        top_5_endpoints = df['request'].value_counts().head(5)
    
    top_5_endpoints_list = [{'endpoint': str(k), 'count': int(v)} for k, v in top_5_endpoints.items()]

    # Traffic over time (Resample using the 'dt' column we created)
    try:
        by_hour = df.set_index('dt').resample('h').size()
        requests_over_time = [{'time': str(k), 'count': int(v)} for k, v in by_hour.items()]
    except Exception as e:
        print(f"Date Resample Error: {e}")
        requests_over_time = []

    return jsonify({
        'total': total,
        'unique_ips': unique_ips,
        'error_rate_pct': error_rate_pct,
        'top_5_ips': top_5_ips_list,
        'top_5_endpoints': top_5_endpoints_list,
        'requests_over_time': requests_over_time,
    })

# ---------------------------------------------------------------------------
# /analyze - GEMINI INTEGRATION (Auto-Detect Model Version)
# ---------------------------------------------------------------------------
ANALYZE_SYSTEM_PROMPT = (
    "You are a Cyber Security Analyst. Analyze these log lines. "
    "Return a VALID JSON object with keys: 'patterns_detected' (list of strings like 'SQL Injection'), "
    "'risk_level', and 'summary'. Do NOT use markdown code blocks. Just return the raw JSON string."
)

def _row_to_log_line(row):
    return f"{row.get('host', '')} - {row.get('time', '')} \"{row.get('request', '')}\" {row.get('status', '')}"

@app.route('/analyze', methods=['POST'])
def analyze():
    global df
    if df is None or df.empty:
        return jsonify({'error': 'No logs loaded.'}), 400

    try:
        # 1. Filter Suspicious Logs
        suspicious = df[
            (df['status'] >= 400) | 
            (df['request'].str.contains('admin|login|UNION|SELECT|etc/passwd', case=False, na=False))
        ]
        if suspicious.empty:
             suspicious = df[df['status'] >= 400]

        # 2. Sample Data
        sample = suspicious.sample(n=min(15, len(suspicious)), random_state=42)
        log_lines = sample.apply(_row_to_log_line, axis=1).tolist()
        log_block = '\n'.join(log_lines)

        # 3. Configure API
        api_key = os.getenv('GEMINI_API_KEY')
        if not api_key:
            return jsonify({'error': 'GEMINI_API_KEY not set in .env'}), 500
        genai.configure(api_key=api_key)
        
        full_prompt = f"{ANALYZE_SYSTEM_PROMPT}\n\nLogs to analyze:\n{log_block}"

        # ---------------------------------------------------------
        # THE FIX: Try all common model names until one works
        # ---------------------------------------------------------
        possible_models = [
            'gemini-1.5-flash',      # Newest Fast Model
            'gemini-1.5-flash-001',  # Versioned Fast Model
            'gemini-1.5-pro',        # High Intelligence
            'gemini-pro',            # Legacy Stable Model
            'gemini-1.0-pro'         # Legacy Versioned
        ]

        response = None
        last_error = ""

        for model_name in possible_models:
            try:
                # print(f"Trying model: {model_name}...") # Uncomment for debugging
                model = genai.GenerativeModel(model_name)
                response = model.generate_content(full_prompt)
                # If we get here, it worked!
                break 
            except Exception as e:
                # If this model failed (404), continue to the next one
                last_error = str(e)
                continue

        if not response:
            raise Exception(f"All models failed. Last error: {last_error}")

        # 4. Parse Response
        text = response.text.strip()
        if text.startswith('```'):
            text = text.replace('```json', '').replace('```', '').strip()

        return jsonify(json.loads(text))

    except Exception as e:
        print(f"Analyze Critical Error: {e}")
        return jsonify({
            'patterns_detected': ['Manual Review Required'], 
            'risk_level': 'Unknown', 
            'summary': f'AI analysis failed. Please check API Key. Details: {str(e)}'
        })

        
# ---------------------------------------------------------------------------
# /search
# ---------------------------------------------------------------------------
@app.route('/search', methods=['GET'])
def search():
    global df
    q = request.args.get('q', '').strip()
    if df is None or df.empty or not q:
        return jsonify({'count': 0, 'results': []})

    # Simple string match
    mask = df['request'].astype(str).str.contains(q, case=False, na=False)
    matches = df[mask].head(50)
    
    results = matches.to_dict(orient='records')
    
    # Clean data for JSON (handle NaNs and Timestamps)
    results = [{k: str(v) for k, v in r.items() if k != 'dt'} for r in results]
    
    return jsonify({'count': len(results), 'results': results})

