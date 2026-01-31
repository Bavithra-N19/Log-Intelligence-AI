# NASA Log Intelligence System

A full-stack **Large-Scale Log Intelligence System** that loads 1M+ server logs from a TSV file, computes dashboard statistics, runs AI-powered threat analysis, and provides search over log data.

## Features

- **Load 1M+ Logs** — Load NASA-style access logs from a local `logs.tsv` file (no browser upload).
- **Dashboard** — Total logs, error rate (4xx/5xx), unique IPs, traffic-over-time chart, top 5 IPs and top 5 endpoints.
- **AI Threat Analysis** — Filter suspicious logs and send a sample to an LLM (Gemini) for pattern detection (e.g. SQL injection, brute force, bot scraping).
- **Search** — Full-text search over the `request` field with results shown in a table (time, request, status).

## Tech Stack

| Layer      | Technology                    |
|-----------|-------------------------------|
| Backend   | Python 3, Flask, Flask-CORS   |
| Data      | Pandas (in-memory DataFrame)  |
| LLM       | Google Gemini API             |
| Frontend  | Single-page HTML, Tailwind CSS, Chart.js, Font Awesome |
| Config    | `.env` (e.g. `GEMINI_API_KEY`) |

## Prerequisites

- **Python 3.8+**
- **logs.tsv** — A TSV file in the project root with columns such as: `host`, `logname`, `user`, `time`, `request`, `status`, `bytes`. (NASA access log format; header optional.)

## Setup

1. **Clone or open the project**
   ```bash
   cd hackathon-project
   ```

2. **Create a virtual environment (recommended)**
   ```bash
   python -m venv venv
   # Windows
   venv\Scripts\activate
   # macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install flask flask-cors pandas python-dotenv google-generativeai
   ```

4. **Configure environment**
   - Create a `.env` file in the project root.
   - Add your Gemini API key:
     ```
     GEMINI_API_KEY=your_gemini_api_key_here
     ```

5. **Add log data**
   - Place your log file in the project root and name it **`logs.tsv`** (or update `LOGS_FILE` in `app.py` to match your filename).

## Run the application

From the project root (with the virtual environment activated):

```bash
python app.py
```

Or:

```bash
flask run
```

Then open **http://127.0.0.1:5000** in your browser.

## Usage

1. Click **Load 1M+ Logs** to load `logs.tsv` into memory and refresh the dashboard.
2. View **Total Logs**, **Error Rate (%)**, and **Unique IPs** and the **Traffic Over Time** chart.
3. Use **Run AI Threat Analysis** to get risk level and detected patterns from the LLM.
4. Use the **Search** box to filter logs by the `request` field; results show time, request, and status.

## Project structure

```
hackathon-project/
├── app.py              # Flask backend (routes, Pandas, Gemini)
├── templates/
│   └── index.html      # Single-page dashboard (Tailwind, Chart.js)
├── logs.tsv            # Your log data (TSV)
├── .env                # GEMINI_API_KEY (not committed)
├── requirements.txt    # Optional: pip install -r requirements.txt
└── README.md
```

## API endpoints

| Method | Endpoint   | Description |
|--------|------------|-------------|
| GET    | `/`        | Serves the dashboard (index.html). |
| GET/POST | `/upload` | Loads `logs.tsv` from disk into memory. Returns `{ "message": "Successfully loaded N logs." }`. |
| GET    | `/stats`   | Returns total, unique_ips, error_rate_pct, top_5_ips, top_5_endpoints, requests_over_time. |
| POST   | `/analyze` | Runs AI threat analysis on a sample of suspicious logs. Returns risk_level, patterns_detected, summary. |
| GET    | `/search?q=` | Filters logs where `request` contains `q`. Returns up to 50 results (time, request, status, etc.). |

## License

MIT (or as required by your hackathon).
