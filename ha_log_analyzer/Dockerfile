ARG BUILD_FROM
FROM ${BUILD_FROM}

RUN pip3 install --no-cache-dir "aiohttp>=3.9" markdown

COPY app/ /app/
COPY rootfs/ /

RUN chmod a+x /etc/services.d/ha_log_analyzer/run
