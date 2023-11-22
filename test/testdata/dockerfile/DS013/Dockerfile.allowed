FROM nginx:2.2
WORKDIR /usr/share/nginx/html
USER mike
CMD cd /usr/share/nginx/html && sed -e s/Docker/\"$AUTHOR\"/ Hello_docker.html > index.html ; nginx -g 'daemon off;'