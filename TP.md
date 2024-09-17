# TP1 : Héberger un service

🌞 **Boom ça commence direct : je veux l'état initial du firewall**

````bash
ad@prx:~/TP_LEO$ sudo ufw status verbose
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
22/tcp (v6)                ALLOW IN    Anywhere (v6)
````

🌞 **Fichiers /etc/sudoers /etc/passwd /etc/group** dans le dépôt de compte-rendu svp !

````bash
ad@prx:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:102:105::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:103:106:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
syslog:x:104:111::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:113:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:116::/run/uuidd:/usr/sbin/nologin
systemd-oom:x:108:117:systemd Userspace OOM Killer,,,:/run/systemd:/usr/sbin/nologin
tcpdump:x:109:118::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
kernoops:x:113:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
avahi:x:114:121:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin
cups-pk-helper:x:115:122:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
rtkit:x:116:123:RealtimeKit,,,:/proc:/usr/sbin/nologin
whoopsie:x:117:124::/nonexistent:/bin/false
sssd:x:118:125:SSSD system user,,,:/var/lib/sss:/usr/sbin/nologin
speech-dispatcher:x:119:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
fwupd-refresh:x:120:126:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
nm-openvpn:x:121:127:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin
saned:x:122:129::/var/lib/saned:/usr/sbin/nologin
colord:x:123:130:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:124:131::/var/lib/geoclue:/usr/sbin/nologin
pulse:x:125:132:PulseAudio daemon,,,:/run/pulse:/usr/sbin/nologin
gnome-initial-setup:x:126:65534::/run/gnome-initial-setup/:/bin/false
hplip:x:127:7:HPLIP system user,,,:/run/hplip:/bin/false
gdm:x:128:134:Gnome Display Manager:/var/lib/gdm3:/bin/false
ad:x:1000:1000:ad,,,:/home/ad:/bin/bash
sshd:x:129:65534::/run/sshd:/usr/sbin/nologin
````
```bash
ad@prx:~$ sudo cat /etc/sudoers
[sudo] password for ad:
#
# This file MUST be edited with the 'visudo' command as root.
#
# Please consider adding local content in /etc/sudoers.d/ instead of
# directly modifying this file.
#
# See the man page for details on how to write a sudoers file.
#
Defaults        env_reset
Defaults        mail_badpass
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
Defaults        use_pty

# This preserves proxy settings from user environments of root
# equivalent users (group sudo)
#Defaults:%sudo env_keep += "http_proxy https_proxy ftp_proxy all_proxy no_proxy"

# This allows running arbitrary commands, but so does ALL, and it means
# different sudoers have their choice of editor respected.
#Defaults:%sudo env_keep += "EDITOR"

# Completely harmless preservation of a user preference.
#Defaults:%sudo env_keep += "GREP_COLOR"

# While you shouldn't normally run git as root, you need to with etckeeper
#Defaults:%sudo env_keep += "GIT_AUTHOR_* GIT_COMMITTER_*"

# Per-user preferences; root won't have sensible values for them.
#Defaults:%sudo env_keep += "EMAIL DEBEMAIL DEBFULLNAME"

# "sudo scp" or "sudo rsync" should be able to use your SSH agent.
#Defaults:%sudo env_keep += "SSH_AGENT_PID SSH_AUTH_SOCK"

# Ditto for GPG agent
#Defaults:%sudo env_keep += "GPG_AGENT_INFO"

# Host alias specification

# User alias specification

# Cmnd alias specification

# User privilege specification
root    ALL=(ALL:ALL) ALL

# Members of the admin group may gain root privileges
%admin ALL=(ALL) ALL

# Allow members of group sudo to execute any command
%sudo   ALL=(ALL:ALL) ALL

# See sudoers(5) for more information on "@include" directives:

@includedir /etc/sudoers.d
```
```bash
ad@prx:~$ sudo cat /etc/group
root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:
fax:x:21:
voice:x:22:
cdrom:x:24:
floppy:x:25:
tape:x:26:
sudo:x:27:ad
audio:x:29:pulse
dip:x:30:
www-data:x:33:
backup:x:34:
operator:x:37:
list:x:38:
irc:x:39:
src:x:40:
gnats:x:41:
shadow:x:42:
utmp:x:43:
video:x:44:
sasl:x:45:
plugdev:x:46:
staff:x:50:
games:x:60:
users:x:100:
nogroup:x:65534:
systemd-journal:x:101:
systemd-network:x:102:
systemd-resolve:x:103:
crontab:x:104:
messagebus:x:105:
systemd-timesync:x:106:
input:x:107:
sgx:x:108:
kvm:x:109:
render:x:110:
syslog:x:111:
_ssh:x:112:
tss:x:113:
bluetooth:x:114:
ssl-cert:x:115:
uuidd:x:116:
systemd-oom:x:117:
tcpdump:x:118:
avahi-autoipd:x:119:
netdev:x:120:
avahi:x:121:
lpadmin:x:122:
rtkit:x:123:
whoopsie:x:124:
sssd:x:125:
fwupd-refresh:x:126:
nm-openvpn:x:127:
scanner:x:128:saned
saned:x:129:
colord:x:130:
geoclue:x:131:
pulse:x:132:
pulse-access:x:133:
gdm:x:134:
lxd:x:135:
ad:x:1000:
sambashare:x:136:
```

## 1. A vos marques

🌞 **Télécharger l'application depuis votre VM**

```bash
ad@prx:~/TP_LEO$ wget https://gitlab.com/it4lik/b3-csec-2024/-/raw/main/efrei_server?ref_type=heads
--2024-09-10 09:42:55--  https://gitlab.com/it4lik/b3-csec-2024/-/raw/main/efrei_server?ref_type=heads
Resolving gitlab.com (gitlab.com)... 172.65.251.78, 2606:4700:90:0:f22e:fbec:5bed:a9b9
Connecting to gitlab.com (gitlab.com)|172.65.251.78|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 7213419 (6,9M) [application/octet-stream]
Saving to: 'efrei_server?ref_type=heads'

efrei_server?ref_type 100%[========================>]   6,88M  5,64MB/s    in 1,2s

2024-09-10 09:42:57 (5,64 MB/s) - 'efrei_server?ref_type=heads' saved [7213419/7213419]
ad@prx:~/TP_LEO$ ls
'efrei_server?ref_type=heads'
ad@prx:~/TP_LEO$ file efrei_server\?ref_type\=heads
efrei_server?ref_type=heads: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f03d903a6268032095b0f6f60b19b3f1d9df99c3, for GNU/Linux 3.2.0, stripped
ad@prx:~/TP_LEO$ mv efrei_server\?ref_type\=heads efrei_server
```

🌞 **Lancer l'application `efrei_server`**


````bash
ad@prx:~/TP_LEO$ export LISTEN_ADDRESS=192.168.202.4
ad@prx:~/TP_LEO$ echo $LISTEN_ADDRESS
192.168.202.4
````

````bash
ad@prx:~/TP_LEO$ ./efrei_server
ad@prx:~/TP_LEO$ ./efrei_server
Server started. Listening on ('192.168.202.4', 8888)...
````

🌞 **Prouvez que l'application écoute sur l'IP que vous avez spécifiée**

````bash
ad@prx:~$ sudo ss -ltnp | grep 192
LISTEN 0      100    192.168.202.4:8888      0.0.0.0:*    users:(("main.bin",pid=5540,fd=6))
````

## 2. Prêts

🌞 **Se connecter à l'application depuis votre PC**

````bash
ad@prx:~$ nc 192.168.202.4 8888
Hello ! Tu veux des infos sur quoi ?
1) cpu
2) ram
3) disk
4) ls un dossier

Ton choix (1, 2, 3 ou 4) :
````

## 3. Hackez

🌞 **Euh bah... hackez l'application !**

````bash
Hello ! Tu veux des infos sur quoi ?
1) cpu
2) ram
3) disk
4) ls un dossier

Ton choix (1, 2, 3 ou 4) : 4
Exécuter la commande ls vers le dossier : ;ls /

efrei_server
bin
boot
cdrom
dev
etc
home
lib
lib32
lib64
libx32
lost+found
media
mnt
opt
proc
root
run
sbin
snap
srv
swapfile
sys
tmp
usr
var
````


🌟 **BONUS : DOS l'application**


## II. Servicer le programme

## 1. Création du service

🌞 **Créer un service `efrei_server.service`**

````bash
ad@prx:~/TP_LEO$ cat /etc/systemd/system/efrei_server.service
[Unit]
Description=Super serveur EFREI

[Service]
ExecStart=/home/ad/TP_LEO/efrei_server
EnvironmentFile=/home/ad/TP_LEO/efrei_server.env
````

````bash
ad@prx:~/TP_LEO$ systemctl daemon-reload
==== AUTHENTICATING FOR org.freedesktop.systemd1.reload-daemon ===
Authentication is required to reload the systemd state.
Authenticating as: ad,,, (ad)
Password:
==== AUTHENTICATION COMPLETE ===
````

## 2. Tests

🌞 **Exécuter la commande `systemctl status efrei_server`**

````bash
ad@prx:~/TP_LEO$ systemctl status efrei_server
* efrei_server.service - Super serveur EFREI
     Loaded: loaded (/etc/systemd/system/efrei_server.service; static)
     Active: inactive (dead)
````


🌞 **Démarrer le service**

````bash
ad@prx:~/TP_LEO$ systemctl start efrei_server.service
==== AUTHENTICATING FOR org.freedesktop.systemd1.manage-units ===
Authentication is required to start 'efrei_server.service'.
Authenticating as: ad,,, (ad)
Password:
==== AUTHENTICATION COMPLETE ===
````

🌞**Vérifier que le programme tourne correctement**

- avec une commande systemctl adaptée, afficher le statut du service efrei_server

````bash
ad@prx:~/TP_LEO$ sudo systemctl status efrei_server
* efrei_server.service - Super serveur EFREI
     Loaded: loaded (/etc/systemd/system/efrei_server.service; static)
     Active: active (running) since Tue 2024-09-10 16:14:08 CEST; 1s ago
   Main PID: 6934 (efrei_server)
      Tasks: 2 (limit: 20412)
     Memory: 33.3M
        CPU: 92ms
     CGroup: /system.slice/efrei_server.service
             |-6934 /home/ad/TP_LEO/efrei_server
              -6935 /home/ad/TP_LEO/efrei_server

sept. 10 16:14:08 prx systemd[1]: Started Super serveur EFREI.
````

- avec une commande ss adaptée, prouver que le programme écoute sur l'adresse IP souhaitée

````bash
ad@prx:~/TP_LEO$ ss -l | grep 192
u_dgr UNCONN 0      0                                                  * 31929                           * 0
tcp   LISTEN 0      100                                    192.168.202.4:8888                      0.0.0.0
````

- depuis votre PC, connectez-vous au service, en utilisant une commande nc

````bash
ad@prx:~$ nc 192.168.202.4 8888
Hello ! Tu veux des infos sur quoi ?
1) cpu
2) ram
3) disk
4) ls un dossier

Ton choix (1, 2, 3 ou 4) :
````

## III. MAKE SERVICES GREAT AGAIN

#### 1. Restart automatique

🌞 **Ajoutez une clause dans le fichier `efrei_server.service` pour le restart automatique**
- c'est la clause `Restart=`
- trouvez la valeur adaptée pour qu'il redémarre tout le temps, dès qu'il est coupé

````bash
ad@prx:~/TP_LEO$ cat /etc/systemd/system/efrei_server.service
[Unit]
Description=Super serveur EFREI

[Service]
ExecStart=/home/ad/TP_LEO/efrei_server
EnvironmentFile=/home/ad/TP_LEO/efrei_server.env
Restart=always
````

🌞 **Testez que ça fonctionne**

- lancez le _service_ avec une commande `systemctl`
```bash
ad@prx:~/TP_LEO$ sudo systemctl daemon-reload
ad@prx:~/TP_LEO$ sudo systemctl restart efrei_server.service
ad@prx:~/TP_LEO$ sudo systemctl status efrei_server.service
* efrei_server.service - Super serveur EFREI
     Loaded: loaded (/etc/systemd/system/efrei_server.service; static)
     Active: active (running) since Tue 2024-09-10 17:07:26 CEST; 9s ago
   Main PID: 7168 (efrei_server)
      Tasks: 2 (limit: 20412)
     Memory: 33.2M
        CPU: 636ms
     CGroup: /system.slice/efrei_server.service
             |-7168 /home/ad/TP_LEO/efrei_server
             `-7171 /home/ad/TP_LEO/efrei_server

sept. 10 17:07:26 prx systemd[1]: Started Super serveur EFREI.
```

- affichez le processus lancé par _systemd_ avec une commande `ps`
    - je veux que vous utilisiez une commande avec `| grep quelquechose` pour n'afficher que la ligne qui nous intéresse
    - vous devriez voir un processus `efrei_server` qui s'exécute

````
ad@prx:~/TP_LEO$ ps aux | grep efrei_server
root        4307  2.8  0.0   3100  2164 ?        Ss   10:15   0:00 /home/ad/TP_LEO/efrei_server
````

- tuez le processus manuellement avec une commande `kill`

````bash
sudo kill 7200
````

- constatez que :
    - le service a bien été relancé
    - il y a bien un nouveau processus `efrei_server` qui s'exécute
    
````bash
ps aux | grep efrei
root        4315  0.1  0.0   3100  2168 ?        Ss   10:16   0:00 /home/ad/TP_LEO/efrei_server
````


#### 2. Utilisateur applicatif

🌞 **Créer un utilisateur applicatif**

- c'est lui qui lancera `efrei_server`
- avec une commande `useradd`
- choisissez...
    - un nom approprié
    - un homedir approprié
    - un shell approprié
		
```bash
ad@prx:~$ sudo useradd -m -s /bin/bash efrei_user
[sudo] password for ad:
ad@prx:~$ getent passwd efrei_user
efrei_user:x:1001:1001::/home/efrei_user:/bin/bash
```

🌞 **Modifier le service pour que ce nouvel utilisateur lance le programme `efrei_server`**

- je vous laisse chercher la clause appropriée à ajouter dans le fichier `.service`

```bash
ad@prx:~$ sudo vim /etc/systemd/system/efrei_server.service
ad@prx:~$ cat /etc/systemd/system/efrei_server.service
[Unit]
Description=Super serveur EFREI

[Service]
ExecStart=/home/ad/TP_LEO/efrei_server
EnvironmentFile=/home/ad/TP_LEO/efrei_server.env
Restart=always
User=efrei_user
Group=efrei_user
```

🌞 **Vérifier que le programme s'exécute bien sous l'identité de ce nouvel utilisateur**

- avec une commande `ps`
- encore là, filtrez la sortie avec un `| grep`
- n'oubliez pas de redémarrer le service pour que ça prenne effet hein !

```bash
efrei_user  4307  0.0  0.0   3100  2164 ?        Ss   22:23   0:00 /home/ad/TP_LEO/efrei_server
```

### 3. Maîtrisez l'emplacement des fichiers

🌞 **Choisir l'emplacement du fichier de logs**
- créez un dossier dédié dans `/var/log/` (le dossier standard pour stocker les logs)
- indiquez votre nouveau dossier de log à l'application avec la variable `LOG_DIR`
- l'application créera un fichier `server.log` à l'intérieur

```bash
ad@prx:~$ sudo mkdir /var/log/efrei_server
ad@prx:~$ LOG_DIR=/var/log/efrei_server
ad@prx:~$ echo $LOG_DIR
/var/log/efrei_server
```

🌞 **Maîtriser les permissions du fichier de logs**

- avec les commandes `chown` et `chmod`
- appliquez les permissions les plus restrictives possibles sur le dossier dans `var/log/`
```bash
ad@prx:~$ sudo chown efrei_user:efrei_user /var/log/efrei_server
ad@prx:~$ ll /var/log/efrei_server/
total 8
drwxr-xr-x  2 efrei_user efrei_user 4096 sept.  17 22:34 ./
```

```bash
ad@prx:~$ sudo chmod 700 /var/log/efrei_server
```

### 4. Security hardening
🌞 Modifier le .service pour augmenter son niveau de sécurité

- ajoutez au moins 5 clauses dans le fichier pour augmenter le niveau de sécurité de l'application
- n'utilisez que des clauses que vous comprenez, useless sinon

```bash
ad@prx:~$ sudo vim /etc/systemd/system/efrei_server.service
 17L, 347B written
ad@prx:~$ sudo cat /etc/systemd/system/efrei_server.service
[Unit]
Description=Super serveur EFREI

[Service]
ExecStart=/home/ad/TP_LEO/efrei_server
EnvironmentFile=/home/ad/TP_LEO/efrei_server.env
Restart=always
User=efrei_user
Group=efrei_user
ProtectSystem=yes
ProtectHome=yes
NoNewPrivileges=true
ReadOnlyPaths=/home/ad/TP_LEO
ReadWritePaths=/var/log/efrei_server

[Install]
WantedBy=multi-user.target

ad@prx:~$ sudo systemctl daemon-reload
ad@prx:~$ sudo systemctl restart efrei_server.service
```
