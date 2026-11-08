FROM python:latest
ADD . /app
WORKDIR /app
RUN pip install --no-cache-dir poetry && poetry install
CMD ["python", "-m", "app"]
