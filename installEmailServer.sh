#!/bin/bash

red=`tput setaf 1`
green=`tput setaf 2`
yellow=`tput setaf 3`
reset=`tput sgr0`

function readValue {
	read -p "$green$1$reset" $2
}

function printText {
	echo "$yellow$1$reset"
}

readValue "Enter domain name (ex. mydomain.com):" domain
printText "Using $domain as domain name"

choice=""
until [[ $choice =~ ^y|Y|n|N$ ]];do
	readValue "Do you have a SSL certificate (y/n)?" choice
	crtFile="/etc/ssl/certs/server.crt"
	keyFile="/etc/ssl/private/server.key"

	case "$choice" in 
	  y|Y ) 
			printText "Leave blank for default values. Default values are: $crtFile and $keyFile respectively."
			readValue "Type the full path for the .crt file:" newCrtFile
			readValue "Type the full path for the .key file:" newKeyFile
			
			if [[ ! -z "$newCrtFile" ]]; then
				$crtFile = $newCrtFile
			fi
			if [[ ! -z "$newKeyFile" ]]; then
				$keyFile = $newKeyFile
			fi
	  ;;
	  n|N ) printText "Generating certificate $crtFile and $keyFile"
			printText "When prompted for Common Name type the domain name!"
			openssl req -new -x509 -nodes -out $crtFile -keyout $keyFile -days 365
			chmod 0600 $keyFile
			openssl dhparam -out /etc/ssl/dhparams.pem 2048
	  ;;
	  * ) printText "Invalid answer";;
	esac
done

#Install email server and web server
printText "Installing postfix and dovecot"

pacman -S postfix dovecot

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
virtual_mailbox_base = /mail
virtual_mailbox_maps = hash:/etc/postfix/vmailbox
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
smtpd_tls_loglevel = 1

smtpd_recipient_restrictions =  permit_sasl_authenticated, permit_mynetworks, reject_unauth_destination
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

#Anti-SPAM
smtpd_helo_required = yes
smtpd_helo_restrictions =
        permit_mynetworks,
        permit_sasl_authenticated,
        reject_invalid_helo_hostname,
        reject_non_fqdn_helo_hostname,
        reject_unknown_helo_hostname,
		check_helo_access hash:/etc/postfix/helo_access
"

hello_access="$domain         REJECT          Get lost - you're lying about who you are
mail.$domain     REJECT          Get lost - you're lying about who you are"

#Enable STARTTLS on port 587
sed -i 's/#submission/submission/g' /etc/postfix/master.cf
sed -i 's/#  -o smtpd_tls_security_level=encrypt/   -o smtpd_tls_security_level=encrypt/g' /etc/postfix/master.cf

echo "$postfix_config" >> /etc/postfix/main.cf
echo "$hello_access" > /etc/postfix/helo_access

touch /etc/dovecot/dovecot.conf

printText "Setting postfix users for $domain"
printText "Type a username and press enter. To finish - leave blank and press enter"

username="\n"
until [ "a$username" == "a" ];do
   
   readValue "Enter username: " username
   if [[ ! -z "$username" ]]; then
		echo "$username@$domain	$domain/$username/" >> /etc/postfix/vmailbox
		password="$(doveadm pw)"
		
		echo "$username@$domain:$password" >> /etc/dovecot/virtual-users
		printText "Username $username set!"
   fi
  
done

echo "@$domain	$domain/anyone/" >> /etc/postfix/vmailbox

readValue "Type the username that will receive root mail: "rootMailUser
echo "root:	$rootMailUser" >> /etc/postfix/aliases

printText "Creating mail folders"
mkdir /mail
chown postfix:postfix /mail

printText "Reloading aliases and generating .db files"
postalias /etc/postfix/aliases
postmap   /etc/postfix/vmailbox
postmap   /etc/postfix/virtual
postmap   /etc/postfix/helo_access


#Configuring dovecot
printText "Configuring dovecot"
dovecot_config="## Dovecot configuration file

# virtual users

disable_plaintext_auth = yes
auth_verbose = yes

auth_mechanisms = plain cram-md5

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

mail_location = maildir:~/
passdb  {
  driver=passwd-file
  args = /etc/dovecot/virtual-users 
}

userdb {
  driver=static
  args = uid=postfix gid=postfix home=/mail/%d/%n
}

ssl_cert = </etc/ssl/certs/server.crt
ssl_key = </etc/ssl/private/server.key

first_valid_uid = 73

#Protect against Logjam attacks
ssl_protocols = !SSLv2 !SSLv3
ssl_cipher_list = ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA
ssl_prefer_server_ciphers = yes
ssl_dh_parameters_length = 2048
"

echo "$dovecot_config" > /etc/dovecot/dovecot.conf

#Configuring folders for dovecot
cp /usr/share/doc/dovecot/example-config/conf.d/20-imap.conf /etc/dovecot/conf.d/
sed -i 's/#mail_plugins = $mail_plugins/mail_plugins = $mail_plugins autocreate/g' /etc/dovecot/conf.d/20-imap.conf

mail_plugin="
plugin {
	autocreate = Trash
	autocreate2 = Junk
	autocreate3 = Drafts
	autocreate4 = Sent
	autosubscribe = Trash
	autosubscribe2 = Junk
	autosubscribe3 = Drafts
	autosubscribe4 = Sent
}"

echo "$mail_plugin" >> /etc/dovecot/conf.d/20-imap.conf

printText "Starting postfix and dovecot"
systemctl enable dovecot.service
systemctl start dovecot
systemctl enable postfix.service
systemctl start postfix

exit 0
