# SBOM license evaluation service.
# Pure standard-library Python: the build needs no network access.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000

WORKDIR /srv

COPY app ./app
COPY tests ./tests
COPY scripts ./scripts

RUN chmod +x scripts/verify.sh \
    && useradd --system --uid 10001 --no-create-home appuser \
    && chown -R appuser:appuser /srv

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=12 \
    CMD python3 -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','8000')+'/health',timeout=2)" || exit 1

CMD ["python3", "-m", "app.server"]
