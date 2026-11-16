FROM debian:latest
ADD . /srv/app
RUN apt-get update && apt-get install -y curl
RUN cd /srv/app && sudo ./install.sh
CMD /srv/app/run.sh
