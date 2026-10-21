FROM python:3.12-alpine
WORKDIR /app
COPY enshrouded_watch.py killers.json ./
ENV PYTHONUNBUFFERED=1 ENSHROUDED_WATCH_CONFIG=/config/config.json
# USER 1000:1000   # optional: run as the owner of the server files
ENTRYPOINT ["python", "/app/enshrouded_watch.py"]
CMD ["run"]
