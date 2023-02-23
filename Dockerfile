#FROM alpine:3.11.5 as build
#
#RUN echo "http://mirrors.aliyun.com/alpine/latest-stable/main/" > /etc/apk/repositories && \
#        echo "http://mirrors.aliyun.com/alpine/latest-stable/community/" >> /etc/apk/repositories && \
#        apk update --allow-untrusted
#RUN apk add --allow-untrusted lxcfs containerd 
#
#FROM alpine:3.11.5
#
#COPY --from=build /usr/bin/lxcfs /usr/bin/lxcfs
#COPY --from=build /usr/lib/*fuse* /usr/lib/
#COPY --from=build /usr/bin/ctr /usr/bin/ctr
#
#COPY ./scripts/start.sh /
#RUN chmod 755 /start.sh
#COPY ./debug-agent /bin/debug-agent
#
#EXPOSE 10027
#CMD ["/start.sh"]

FROM ubuntu:20.04

RUN apt-get update && apt-get install -y --no-install-recommends \
	lxcfs \
	containerd
#RUN sed -i "s@/archive.ubuntu.com/@/mirrors.aliyun.com/@g" /etc/apt/sources.list
#RUN sed -i "s@/security.ubuntu.com/@/mirrors.aliyun.com/@g" /etc/apt/sources.list

COPY ./scripts/start.sh /
RUN chmod 755 /start.sh
COPY ./debug-agent /bin

EXPOSE 10027
CMD ["/start.sh"]
