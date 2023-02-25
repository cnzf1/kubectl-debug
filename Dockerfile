FROM alpine as build

RUN echo "http://mirrors.aliyun.com/alpine/latest-stable/main/" > /etc/apk/repositories && \
    echo "http://mirrors.aliyun.com/alpine/latest-stable/community/" >> /etc/apk/repositories && \
    apk update --allow-untrusted && \
    apk add --allow-untrusted lxcfs containerd 

FROM alpine

COPY --from=build /usr/bin/lxcfs /usr/bin/lxcfs
COPY --from=build /usr/lib/*fuse* /usr/lib/
COPY --from=build /usr/bin/ctr /usr/bin/ctr

COPY ./scripts/start.sh /
RUN chmod 755 /start.sh

COPY ./debugger /bin

EXPOSE 10027
CMD ["/start.sh"]