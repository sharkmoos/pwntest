FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt install --no-install-recommends -y openssh-server openssh-client  && \
    useradd -rm -d /home/david -s /bin/bash -u 3232 david && \
    echo 'david:foobar' | chpasswd

RUN chmod +s /bin/bash && \
    service ssh start && \
    echo "pwntest{test_flag}" > /root/root.txt

EXPOSE 22
ENTRYPOINT ["/usr/sbin/sshd","-D"]
