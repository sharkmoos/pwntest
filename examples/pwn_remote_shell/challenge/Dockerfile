FROM ubuntu:20.04 as builder
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install --no-install-recommends -qy libc6-dev gcc && \
    useradd -m ctf

WORKDIR /home/ctf

ARG COMPILE_CHALLENGE
ENV COMPILE=${COMPILE_CHALLENGE}

COPY ./bin/ /home/ctf/
RUN $COMPILE && rm challenge.c

FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install --no-install-recommends -qy libc6-dev xinetd && \
    useradd -m ctf

WORKDIR /home/ctf

COPY ./ctf.xinetd /etc/xinetd.d/ctf
COPY ./start.sh /start.sh

RUN echo "Blocked by ctf_xinetd" > /etc/banner_fail && \
    chmod +x /start.sh

EXPOSE 9999

COPY --from=builder /home/ctf/ /home/ctf/

RUN chmod +x challenge && \
    chown -R root:ctf /home/ctf && \
    chmod -R 750 /home/ctf && \
    chmod 740 /home/ctf/flag

CMD ["/start.sh"]
