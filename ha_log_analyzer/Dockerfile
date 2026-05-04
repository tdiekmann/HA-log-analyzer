ARG BUILD_FROM=python:3.12-alpine
FROM ${BUILD_FROM}

RUN pip3 install --no-cache-dir "aiohttp>=3.9" markdown

WORKDIR /app
COPY app/ /app/
COPY run.sh /run.sh

RUN chmod +x /run.sh

CMD ["/run.sh"]
