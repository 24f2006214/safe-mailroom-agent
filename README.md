# Safe AI Mailroom Agent

## Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

The public endpoint is `/mailroom`.

## Render

Create a Web Service from this folder's GitHub repository. Use:

- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`

Submit the endpoint URL, for example `https://your-service.onrender.com/mailroom`.

