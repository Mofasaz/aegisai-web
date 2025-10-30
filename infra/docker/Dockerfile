FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY api ./api
COPY rules ./rules
COPY retrieval ./retrieval
COPY data ./data
# non-root user for OpenShift SCC
RUN addgroup --system app && adduser --system --ingroup app appuser
USER appuser
EXPOSE 8000
CMD ["uvicorn","api.main:app","--host","0.0.0.0","--port","8000"]
