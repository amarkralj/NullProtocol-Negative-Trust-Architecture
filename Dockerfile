FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN pip install --no-cache-dir . && useradd -r npcore
USER npcore
EXPOSE 8080
# mount your directory file at /config/directory.json
CMD ["npcore", "serve", "--host", "0.0.0.0", "--port", "8080", "--directory", "/config/directory.json"]
