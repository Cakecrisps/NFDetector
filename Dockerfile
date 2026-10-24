FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY requirements.txt requirements-server.txt ./
RUN pip install --no-cache-dir -r requirements-server.txt \
    && groupadd --gid 10001 nfdetect \
    && useradd --uid 10001 --gid 10001 --no-create-home nfdetect \
    && mkdir /data && chown nfdetect:nfdetect /data
COPY general ./general
COPY distributed ./distributed
COPY rules.json ./rules.json
COPY ext ./ext
USER 10001:10001
ENTRYPOINT ["python", "-m", "distributed"]
CMD ["api"]
