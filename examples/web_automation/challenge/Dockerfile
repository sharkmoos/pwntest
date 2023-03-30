FROM python:3.10-slim

RUN apt update && apt install --no-install-recommends -y ncat

COPY requirements.txt /tmp
RUN pip3 install -r /tmp/requirements.txt

WORKDIR /app

COPY app ./

EXPOSE 5000
ENTRYPOINT ["python3", "app.py"]