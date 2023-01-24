FROM python:3.10-slim

RUN apt update && apt install --no-install-recommends -y ncat \
    && pip3 install flask

WORKDIR /app

COPY app ./

EXPOSE 5000
ENTRYPOINT ["python3", "app.py"]