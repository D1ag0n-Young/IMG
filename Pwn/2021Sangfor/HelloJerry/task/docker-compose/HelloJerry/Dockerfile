FROM ubuntu:20.04

RUN sed -i s@/archive.ubuntu.com/@/mirrors.aliyun.com/@g /etc/apt/sources.list

RUN apt-get -y update && \
    apt-get -y dist-upgrade && \
    apt-get -y install xinetd python lib32z1 

RUN groupadd -g 1000 ctf && \
    useradd -g ctf -m -u 1000 ctf -s /bin/bash

COPY ./src/flag /home/ctf/flag

COPY ./src/jerry /home/ctf/jerry

RUN chmod +x /home/ctf/jerry

COPY ./src/server.py /opt/server.py

COPY ./src/start.sh /opt/start.sh

RUN chmod +x /opt/start.sh

COPY xinetd.conf /etc/xinetd.d/chall
RUN chown -R root:ctf /home/ctf && \
    chmod -R 750 /home/ctf && \
    chmod 740 /home/ctf/flag

CMD ["/usr/sbin/xinetd", "-dontfork"]
