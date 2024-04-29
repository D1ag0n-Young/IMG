FROM fedora:39
RUN sed -e 's|^metalink=|#metalink=|g' \
         -e 's|^#baseurl=http://download.example/pub/fedora/linux|baseurl=https://mirrors.ustc.edu.cn/fedora|g' \
         -i.bak \
         /etc/yum.repos.d/fedora.repo \
         /etc/yum.repos.d/fedora-updates.repo
RUN dnf makecache
RUN dnf update -y && dnf install -y qemu-user wget
RUN mkdir /chall
WORKDIR /chall
COPY ./libc libc
COPY ./socaz /usr/local/bin/
COPY ./chall ./start.sh ./flag.txt .
RUN chmod +x ./start.sh
CMD ["./start.sh"]
