#!/bin/sh


# Disable SSH
rm -rf /etc/service/sshd /etc/my_init.d/00_regen_ssh_host_keys.sh

#add app user to bind group
usermod -a -G bind app

#set owner for app folder
chown app:app /home/ddns/app

#change owner of rndc key
chown root:bind /etc/bind/rndc.key

#add control with rndc
cat <<'EOT' >> /etc/bind/named.conf
include "/etc/bind/rndc.key";
controls {
        inet 127.0.0.1 allow { localhost; } keys { "rndc-key"; };
};
EOT

#BIND9 startup
mkdir -p /etc/service/bind
cat <<'EOT' > /etc/service/bind/run
#!/bin/bash
exec /usr/sbin/named -u bind -g
EOT

#derp make it executable
chmod +x /etc/service/bind/run

#runonce config script
cat <<'EOT' > /etc/my_init.d/runonce.sh
#!/bin/bash
echo "include \"/etc/bind/${DDNS}.keys\";" > /etc/bind/named.conf.local
echo "" >> /etc/bind/named.conf.local
echo "zone \"${DDNS}\" {" >> /etc/bind/named.conf.local
echo "        type master;" >> /etc/bind/named.conf.local
echo "        file \"/var/lib/bind/${DDNS}\";" >> /etc/bind/named.conf.local
echo "        update-policy {" >> /etc/bind/named.conf.local
echo "        grant *.${DDNS} selfsub ${DDNS}.;" >> /etc/bind/named.conf.local
echo "        };" >> /etc/bind/named.conf.local
echo "};" >> /etc/bind/named.conf.local

touch /etc/bind/${DDNS}.keys
chmod 664 /etc/bind/${DDNS}.keys
chown root:bind /etc/bind/${DDNS}.keys

export HOST=`echo "${DDNS}" | sed  "s/^[^\.]*\.//"`
export PUB_IP=`dig @ns1.google.com -t txt o-o.myaddr.l.google.com +short | sed 's/"//g'`

echo "\$ORIGIN ." >> /var/lib/bind/${DDNS}
echo "\$TTL 60 ; 1 minute" >> /var/lib/bind/${DDNS}
echo "${DDNS}		IN SOA ns1.${DDNS}. root.${HOST}. (" >> /var/lib/bind/${DDNS}
echo "			1 ; serial" >> /var/lib/bind/${DDNS}
echo "			3600 ; refresh (1 hour)" >> /var/lib/bind/${DDNS}
echo "			600 ; retry (10 minutes)" >> /var/lib/bind/${DDNS}
echo "			604800 ; expire (1 week)" >> /var/lib/bind/${DDNS}
echo "			300 ; minimum (5 minutes)" >> /var/lib/bind/${DDNS}
echo "			)" >> /var/lib/bind/${DDNS}
echo "			NS ns1.${DDNS}. " >> /var/lib/bind/${DDNS}
echo "			A ${PUB_IP}" >> /var/lib/bind/${DDNS}
echo "\$ORIGIN ${DDNS}." >> /var/lib/bind/${DDNS}
echo "\$TTL 60 ; 1 minute" >> /var/lib/bind/${DDNS}
echo "ns1		A ${PUB_IP}" >> /var/lib/bind/${DDNS}

chown bind:bind /var/lib/bind/${DDNS}

rm /etc/my_init.d/runonce.sh
EOT
chmod +x /etc/my_init.d/runonce.sh
