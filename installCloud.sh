#!/bin/bash

red=`tput setaf 1`
green=`tput setaf 2`
yellow=`tput setaf 3`
reset=`tput sgr0`
newline=`echo $'\n.'`
newline=${cr%.}

function readValue {
	read -p "$green$1$reset" $2
}

function readPassword {
	read -s -p "$green$1$reset$newline" $2
}
function printText {
	echo "$yellow$1$reset"
}

readValue "Enter domain name (ex. mydomain.com):" domain
printText "Using $domain as domain name"

readValue "Enter the full path for email storage. Leave blank for default. Default value = /mail:" mailPath
readValue "Enter the full path for owncloud storage. Leave blank for default. Default value = /srv/http/$domain/data:" owncloudDataPath

if [ -z "$mailPath" ]; then
	mailPath="/mail"
fi

printText "Setting up locale"
sed -i 's/#en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/g' /etc/locale.gen
locale-gen
localectl set-locale LANG=en_US.UTF-8

#SSL Certificate generation
crtFile="/etc/ssl/certs/$domain.crt"
keyFile="/etc/ssl/private/$domain.key"
pemFile="/etc/ssl/certs/$domain.pem"
dhParamFile="/etc/ssl/dhparams.pem"

choice=""
until [[ $choice =~ ^y|Y|n|N$ ]];do
	readValue "Generate DH param group? [Takes a lot of time] (y/n)?" choice
		
	case "$choice" in 
	  y|Y ) 
			openssl dhparam -out $dhParamFile 2048
	  ;;
	  n|N )
			printText "Moving on..."
	  ;;
	  * ) printText "Invalid answer";;
	esac
done


choice=""
until [[ $choice =~ ^y|Y|n|N$ ]];do
	readValue "Generate self-signed SSL certificate (y/n)?" choice
	
	
	case "$choice" in 
	  y|Y ) 
	  		printText "Generating certificate $crtFile and $keyFile"
			printText "When prompted for Common Name type the domain name!"
			openssl req -new -x509 -nodes -out $crtFile -keyout $keyFile -days 365
			
			if [ -b "$dhParamFile" ] 
			then
				echo $crtFile $dhParamFile > $pemFile
			else
				echo $crtFile > $pemFile
			fi
			
	  ;;
	  n|N ) 
			printText "Leave blank for default values. Default values are: $crtFile, $keyFile and $pemFile respectively."
			readValue "Type the full path for the .crt file:" newCrtFile
			readValue "Type the full path for the .key file:" newKeyFile
			readValue "Type the full path for the .pem file. The .pem file contains the full keychain including the intermediary certificate and DH params if necesary:" newPemFile
			if [[ ! -z "$newCrtFile" ]]; then
				crtFile = $newCrtFile
			fi
			if [[ ! -z "$newKeyFile" ]]; then
				keyFile = $newKeyFile
			fi
			if [[ ! -z "$newPemFile" ]]; then
				pemFile = $newPemFile
			fi
	  ;;
	  * ) printText "Invalid answer";;
	esac
done

#Setting proper permissions for SSL certificate files
chmod 0600 $keyFile
chmod 0600 $crtFile
chmod 0600 $pemFile
chown root:root $keyFile
chown root:root $crtFile
chown root:root $pemFile


#Install email server and web server
printText "Installing postfix, dovecot and owncloud software and dependencies"

pacman -Sy postfix dovecot nginx php php-fpm php-gd php-mcrypt php-intl php-apcu wget sudo unzip


#Postfix configuration
printText "Configuring postfix"

postfix_config="
#Setting up postfix domain name
home_mailbox = Maildir/
myhostname = $domain
mydomain = $domain
mydestination = localhost

#Setting up virtual mailbox and its users
virtual_mailbox_domains = $domain
virtual_mailbox_base = $mailPath
virtual_mailbox_maps = mysql:/etc/postfix/vmailbox-db
virtual_minimum_uid = 50
virtual_uid_maps = static:73
virtual_gid_maps = static:73
virtual_alias_maps = hash:/etc/postfix/virtual
mailbox_size_limit = 0
virtual_mailbox_limit = 0

#Enable SSL for SMTP
smtpd_sasl_auth_enable = yes
smtpd_sasl_local_domain = \$myhostname
smtpd_sasl_security_options = noanonymous
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth

smtpd_tls_security_level=may
smtpd_tls_auth_only = yes
smtpd_tls_cert_file = $crtFile
smtpd_tls_key_file = $keyFile
smtp_tls_cert_file = $crtFile
smtp_tls_key_file = $keyFile
smtpd_tls_loglevel = 1

smtpd_recipient_restrictions = permit_sasl_authenticated, permit_mynetworks, reject_unauth_destination
broken_sasl_auth_clients = no

#Protect against POODLE and FREAK/Logjam attacks
smtpd_tls_mandatory_protocols=!SSLv2,!SSLv3
smtp_tls_mandatory_protocols=!SSLv2,!SSLv3
smtpd_tls_protocols=!SSLv2,!SSLv3
smtp_tls_protocols=!SSLv2,!SSLv3
smtpd_tls_exclude_ciphers = aNULL, eNULL, EXPORT, DES, RC4, MD5, PSK, aECDH, EDH-DSS-DES-CBC3-SHA, EDH-RSA-DES-CDC3-SHA, KRB5-DE5, CBC3-SHA
smtpd_tls_dh1024_param_file = /etc/ssl/dhparams.pem

#Enable e-mail encryption
smtp_tls_security_level=encrypt
smtp_enforce_tls=yes
"

echo "$postfix_config" >> /etc/postfix/main.cf

#Configuring postfix user identification based on owncloud users
vmailbox_db="
user = $owncloudUser
password = $owncloudPassword
hosts = localhost
dbname = $owncloudDatabase
query = SELECT concat('$domain/',uid,'/') FROM oc_users WHERE uid='%s'
"

echo "$vmailbox_db" > /etc/postfix/vmailbox-db
chmod 600 /etc/postfix/vmailbox-db

#Enable STARTTLS on port 587
sed -i 's/#submission/submission/g' /etc/postfix/master.cf
sed -i 's/#  -o smtpd_tls_security_level=encrypt/   -o smtpd_tls_security_level=encrypt/g' /etc/postfix/master.cf


printText "Creating mail folders"
mkdir $mailPath
chown postfix:postfix $mailPath

printText "Reloading aliases and generating .db files"
postalias /etc/postfix/aliases
postmap   /etc/postfix/vmailbox-db
postmap   /etc/postfix/virtual

chown postfix:postfix /etc/postfix/vmailbox-db
chown postfix:postfix /etc/postfix/vmailbox-db.db
chmod 600 /etc/postfix/vmailbox-db.db



#Dovecot configuration
printText "Configuring dovecot"
dovecot_config="## Dovecot configuration file
# virtual users

disable_plaintext_auth = yes
auth_verbose = yes

auth_mechanisms = plain cram-md5

service imap-login {
  inet_listener imap {
    port = 143
  }
  inet_listener imaps {
    port = 0
  }
}

service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix        
  }
  unix_listener auth-userdb {
    mode   = 0600
    user   = postfix
    group  = postfix
  }
}

mail_location = maildir:$mailPath/%d/%n

passdb  {
  driver=sql
  args = /etc/dovecot/virtual-users-db 
}

userdb {
  driver=static
  args = uid=postfix gid=postfix home=$mailPath/%d/%n
}

ssl_cert = <$pemFile
ssl_key = <$keyFile

first_valid_uid = 73

#Protect against Logjam attacks
ssl_protocols = !SSLv2 !SSLv3
ssl_cipher_list = ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA
ssl_prefer_server_ciphers = yes
ssl_dh_parameters_length = 2048

protocol imap {
  namespace inbox {
    inbox = yes

    mailbox Trash {
	  auto = subscribe
	  special_use = \Trash
    }
    mailbox Drafts {
	  auto = subscribe
	  special_use = \Drafts
    }
    mailbox Sent {
	  auto = subscribe
	  special_use = \Sent
    }
    mailbox \"Sent Messages\" {
	  auto = no
	  special_use = \Sent
    }
    mailbox Junk {
	  auto = subscribe
	  special_use = \Junk
    }
  }
}


"

echo "$dovecot_config" > /etc/dovecot/dovecot.conf


#Configuring dovecot user authorization based on owncloud users
virtual_users_db="
driver = mysql
connect = host=localhost dbname=$owncloudDatabase user=$owncloudUser password=$owncloudPassword
default_pass_scheme = CRAM-MD5
password_query = SELECT concat(uid,'@$domain') as user, password FROM oc_users WHERE uid='%u';
"

echo "$virtual_users_db" > /etc/dovecot/virtual-users-db
chmod 600 /etc/dovecot/virtual-users-db


#OwnCloud configuration
sed -i 's/;extension=gd.so/extension=gd.so/g' /etc/php/php.ini
sed -i 's/;extension=iconv.so/extension=iconv.so/g' /etc/php/php.ini
sed -i 's/;extension=xmlrpc.so/extension=xmlrpc.so/g' /etc/php/php.ini
sed -i 's/;extension=zip.so/extension=zip.so/g' /etc/php/php.ini
sed -i 's/;extension=bz2.so/extension=bz2.so/g' /etc/php/php.ini
sed -i 's/;extension=curl.so/extension=curl.so/g' /etc/php/php.ini
sed -i 's/;extension=intl.so/extension=intl.so/g' /etc/php/php.ini
sed -i 's/;extension=mcrypt.so/extension=mcrypt.so/g' /etc/php/php.ini
sed -i 's/;extension=pdo_mysql.so/extension=pdo_mysql.so/g' /etc/php/php.ini
sed -i 's/;extension=mysqli.so/extension=mysqli.so/g' /etc/php/php.ini
sed -i 's/;zend_extension=opcache.so/zend_extension=opcache.so/g' /etc/php/php.ini
sed -i 's/;extension=apcu.so/extension=apcu.so/g' /etc/php/conf.d/apcu.ini
  
  
readValue "Install MySQL database and configuration for ownCloud (y/n)?" choice
case "$choice" in 
  n|N ) printText "Type the connection information for the existing ownCloud database"
		
		readValue "Enter the MySQL database name to be used by owncloud (ex. cloud):" owncloudDatabase
		readValue "Enter the MySQL username to be used by owncloud (ex. cloud):" owncloudUser
		readPassword "Type password for user $owncloudUser:" owncloudPassword

  ;;
  y|Y ) printText "Setting up MySQL database"
		pacman -S mariadb
		mysql_install_db --user=mysql --basedir=/usr --datadir=/var/lib/mysql
		systemctl enable mysqld.service
		systemctl start mysqld
		printText "Initializing MySQL root user. Type root password:"
		mysql_secure_installation
		
		readValue "Enter the MySQL database name to be used by owncloud (ex. cloud):" owncloudDatabase
		readValue "Enter the MySQL username to be used by owncloud (ex. cloud):" owncloudUser
		readPassword "Type password for user $owncloudUser:" owncloudPassword

		owncloudSql="CREATE DATABASE $owncloudDatabase;
					CREATE DATABASE rainloop;
					CREATE USER $owncloudUser@localhost;
					SET PASSWORD FOR $owncloudUser@localhost= PASSWORD('$owncloudPassword');
					GRANT ALL PRIVILEGES ON $owncloudUser.* TO $owncloudUser@localhost IDENTIFIED BY '$owncloudPassword';
					FLUSH PRIVILEGES;"


		printText "\nExecuting database script. Type root password:"
		mysql -u root -p -e "$owncloudSql"
	;;
  * ) printText "Invalid answer";;
esac


#Nginx configuration
printText "Configuring nginx"


nginx_config="
worker_processes  1;

events {
    worker_connections  1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;
    sendfile        on;
	
	#Protect against Logjam attacks
	ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA';
	ssl_dhparam /etc/ssl/dhparams.pem;
	ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_prefer_server_ciphers on;
	
	server {
		listen       80;
		server_name  $domain;
		return 301 https://\$server_name\$request_uri;  # enforce https
	}
	
	server {
		listen 443 ssl;
		server_name $domain;
		ssl_certificate $crtFile;
		ssl_certificate_key $keyFile;
		root /srv/http/$domain;
	 
		client_max_body_size 10G; # set max upload size
		fastcgi_buffers 64 4K;
	 
		rewrite ^/caldav(.*)$ /remote.php/caldav\$1 redirect;
		rewrite ^/carddav(.*)$ /remote.php/carddav\$1 redirect;
		rewrite ^/webdav(.*)$ /remote.php/webdav\$1 redirect;
	 
		index index.php;
		error_page 403 /core/templates/403.php;
		error_page 404 /core/templates/404.php;
	 
		location = /robots.txt {
			allow all;
			log_not_found off;
			access_log off;
		}
	 
		location ~ ^/(data|config|\.ht|db_structure\.xml|README) {
			deny all;
		}
	 
		location / {
			# The following 2 rules are only needed with webfinger
			rewrite ^/.well-known/host-meta /public.php?service=host-meta last;
			rewrite ^/.well-known/host-meta.json /public.php?service=host-meta-json last;
	 
			rewrite ^/.well-known/carddav /remote.php/carddav/ redirect;
			rewrite ^/.well-known/caldav /remote.php/caldav/ redirect;
	 
			rewrite ^(/core/doc/[^\/]+/)$ \$1/index.html;
	 
			try_files \$uri \$uri/ index.php;
		}
	 
		location ~ ^(.+?\.php)(/.*)?$ {
			try_files \$1 =404;
	 
			include fastcgi_params;
			fastcgi_param MOD_X_ACCEL_REDIRECT_ENABLED on;
			fastcgi_param SCRIPT_FILENAME \$document_root\$1;
			fastcgi_param PATH_INFO \$2;
			fastcgi_param HTTPS on;
			fastcgi_pass unix:/run/php-fpm/php-fpm.sock;
		}
	 
		location ~ ^$owncloudDataPath {
			internal;
			root /;
		}
	 
		location ~ ^/tmp/oc-noclean/.+$ {
			internal;
			root /;
		}
	 
		# Optional: set long EXPIRES header on static assets
		location ~* ^.+\.(jpg|jpeg|gif|bmp|ico|png|css|js|swf)$ {
			expires 30d;
			# Optional: Don't log access to assets
			access_log off;
		}
	}
}"

echo "$nginx_config" > /etc/nginx/nginx.conf

printText "Downloading and installing owncloud"

wget https://download.owncloud.org/community/owncloud-9.0.2.tar.bz2
tar xfj owncloud-9.0.2.tar.bz2 -C /srv/http
rm owncloud-9.0.2.tar.bz2
mv /srv/http/owncloud /srv/http/$domain

#Overwriting password hash generation for owncloud
hasher_php="<?php
namespace OC\Security;

use OCP\IConfig;
use OCP\Security\IHasher;

class Hasher implements IHasher {
	
	private \$config;
	private \$options = array();
	private \$legacySalt = null;
	private \$currentVersion = 1;

	function __construct(IConfig \$config) {
		\$this->config = \$config;

		\$hashingCost = \$this->config->getSystemValue('hashingCost', null);
		if(!is_null(\$hashingCost)) {
			\$this->options['cost'] = \$hashingCost;
		}
	}

	public function hash(\$message) {
		return exec('doveadm pw -p '.\$message);
	}
	
	public function verify(\$message, \$hash, &\$newHash = null) {
		return (\$this->hash(\$message) == \$hash ? true : false);
	}
}
"

echo "$hasher_php" > /srv/http/$domain/lib/private/security/hasher.php

#Setting proper permissions
chgrp -R http /srv/http/$domain
chmod -R 770 /srv/http/$domain
mkdir $owncloudDataPath
chown http:http $owncloudDataPath


#Init owncloud
printText "Initializing ownCloud"
readValue "Type admin username for owncloud:" adminUser
readPassword "Type admin password for owncloud:" adminPassword	

sudo -u http php /srv/http/$domain/occ  maintenance:install --database "mysql" --database-name "$owncloudDatabase"  --database-user "$owncloudUser" --database-pass "$owncloudUser" --admin-user "$adminUser" --admin-pass "$adminPassword" --data-dir "$owncloudDataPath"

sed -i "s/),/   1 => '$domain',\n  ),/g" /srv/http/$domain/config/config.php
sed -i "s/);/  'memcache.local' => '\\\OC\\\Memcache\\\APCu',\n);/g" /srv/http/$domain/config/config.php
sed -i "s/);/  'appstore.experimental.enabled' => true,\n);/g" /srv/http/$domain/config/config.php
sed -i "s/);/  'defaultapp' => 'rainloop',\n);/g" /srv/http/$domain/config/config.php
  

printText "Installing Contacts app for ownCloud"
wget https://github.com/owncloud/contacts/releases/download/v1.3.1.0/contacts.tar.gz
tar xfz contacts.tar.gz -C /srv/http/$domain/apps
rm contacts.tar.gz
sudo -u http /srv/http/$domain/occ app:enable contacts

printText "Installing Calendar app for ownCloud"
wget https://github.com/owncloud/calendar/releases/download/v1.2.2/calendar.tar.gz
tar xfz calendar.tar.gz -C /srv/http/$domain/apps
rm calendar.tar.gz
sudo -u http /srv/http/$domain/occ app:enable calendar

printText "Installing RainLoop Webmail app for ownCloud"
wget http://repository.rainloop.net/v2/other/owncloud/rainloop.zip
unzip -qq -o rainloop.zip -d /srv/http/$domain/apps
rm rainloop.zip
sudo -u http /srv/http/$domain/occ app:enable rainloop


printText "Starting postfix, dovecot and nginx web server"
systemctl enable dovecot.service
systemctl start dovecot
systemctl enable postfix.service
systemctl start postfix
systemctl enable php-fpm
systemctl start php-fpm
systemctl enable nginx
systemctl start nginx

exit 0
