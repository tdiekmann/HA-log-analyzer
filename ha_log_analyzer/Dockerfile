FROM python:3.12-alpine

RUN pip3 install --no-cache-dir "aiohttp>=3.9" markdown

COPY app/ /app/

CMD ["python3", "/app/main.py"]
