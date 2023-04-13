FROM --platform=linux/amd64 python:3.11-slim@sha256:286f2f1d6f2f730a44108656afb04b131504b610a6cb2f3413918e98dabba67e

RUN apt-get update && apt-get install -y gcc libssl-dev

RUN adduser --disabled-password dragonfly
USER dragonfly

ENV PATH="${PATH}:/home/dragonfly/.local/bin"

# Set Git SHA environment variable
ARG git_sha="development"
ENV GIT_SHA=$git_sha

WORKDIR /app
COPY pyproject.toml src ./
RUN python -m pip install .

EXPOSE 8080

CMD ["uvicorn", "dragonfly.server:app", "--host", "0.0.0.0", "--port", "8080"]
