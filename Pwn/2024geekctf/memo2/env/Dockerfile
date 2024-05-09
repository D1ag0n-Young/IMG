FROM ubuntu:22.04

RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list && \
    apt-get update && apt-get -y dist-upgrade && \
    apt-get install -y xinetd

RUN useradd -u 6666 -m ctf

WORKDIR /home/ctf

COPY ./ctf.xinetd /etc/xinetd.d/ctf
COPY ./start.sh /start.sh
RUN echo "Blocked by ctf_xinetd" > /etc/banner_fail

RUN chmod 700 /start.sh

COPY ./bin/ /home/ctf/
RUN chown -R root:root /home/ctf && \
    chmod -R 755 /home/ctf && \
    chmod 644 /home/ctf/flag && \
    chmod 644 /etc/xinetd.d/ctf 

CMD ["/start.sh"]


