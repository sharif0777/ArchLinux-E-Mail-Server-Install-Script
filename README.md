# ArchLinux-E-Mail-Server-Install-Script

A script designed to automate postfix, dovecot instalation and configuration on ArchLinux.
The script is aimed at creating a configuration that applies to most users' needs.
I've tried to secure postfix and dovecot with the best practices I found online.

If any improvements come to mind please feel free to share.




Features:

  -Postfix configured with STARTTLS on port 25 and 587
  
  -Dovecot configured with STARTTLS on port 993 and SSL/TLS on 143
  
  -Generation of self signed SSL certificate 
  
  -Protection against #POODLE, #FREAK/Logjam attacks by using 2048 bit DH group for both postfix and dovecot
  
  -Configuration of virtual users, encrypted passwords 
  
  -Automatic folder creation and subscribtion: Sent, Drafts, Junk, Trash; for Dovecot
  
