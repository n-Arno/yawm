FROM alpine:latest

COPY requirements.txt /requirements.txt

RUN apk add --no-cache python3 py3-pip tini && \
    pip install -r /requirements.txt --break-system-packages && \
    pip cache purge

COPY main.py /main.py

EXPOSE 8080

ENTRYPOINT ["/sbin/tini","/main.py"]
