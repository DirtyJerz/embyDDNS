
FROM phusion/passenger-customizable:0.9.18
MAINTAINER Mike O'Connor <moconnore@gmail.com>

# Set correct environment variables.
ENV HOME /root

# Use baseimage-docker's init process.
CMD ["/sbin/my_init"]

#   Build system and git.
RUN /pd_build/utilities.sh

#   Python support.
RUN /pd_build/python.sh
RUN apt-get update && apt-get install -y sqlite3 bind9 dnsutils git python-pip python-dev build-essential autoconf libffi-dev libssl-dev nano 
ENV TERM=xterm

#setup app
ADD ddns/app/requirements.txt /home/ddns/app/
RUN pip install -r /home/ddns/app/requirements.txt

ADD ddns/app/__init__.py /home/ddns/app/
ADD ddns/app/api.py /home/ddns/app/
ADD ddns/app/le.py /home/ddns/app/
ADD ddns/passenger_wsgi.py /home/ddns/


#enable nginx for wsgi
RUN rm -f /etc/service/nginx/down

#remove default site
RUN rm /etc/nginx/sites-enabled/default

#add web conf
ADD ddns/api_nginx.conf /etc/nginx/sites-enabled/

RUN install -d -o bind -g bind -m 755 /var/run/named

#run install script
COPY ./install.sh /
RUN chmod +x /install.sh; sync && /install.sh && rm /install.sh

EXPOSE 5000 53 953 53/udp

# Clean up APT when done.
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

