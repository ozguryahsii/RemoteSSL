FROM nginx:alpine
RUN apk add --no-cache openssh openssl && ssh-keygen -A \
 && echo 'root:remotessl' | chpasswd \
 && sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
 && mkdir -p /etc/nginx/ssl \
 && openssl req -x509 -newkey rsa:2048 -keyout /etc/nginx/ssl/server.key \
    -out /etc/nginx/ssl/server.crt -days 30 -nodes -subj "/CN=lab.remotessl.local"
COPY nginx-ssl.conf /etc/nginx/conf.d/ssl.conf
CMD ["/bin/sh","-c","/usr/sbin/sshd && exec nginx -g 'daemon off;'"]
