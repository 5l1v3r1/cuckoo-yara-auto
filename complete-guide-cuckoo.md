# cuckoo-yara-auto & cuckoo install guide

###Cuckoo Installation Guide with additions:


- System Update / Upgrade:

    1) ``apt update && apt dist-upgrade -y  && apt autoremove -y``
     
- Dependency:

    1) ``apt install python gdebi tesseract-ocr python-pip python-dev libffi-dev libssl-dev libfuzzy-dev python-virtualenv python-setuptools libjpeg-dev zlib1g-dev swig virtualbox virtualbox-guest-x11 mongodb -y``
   
- Cuckoo user+virtualenv+cuckoo:

    ```python
        adduser cuckoo
        usermod -a -G vboxusers cuckoo
    ```

    1) ``adduser cuckoo``
    2) ``usermod -a -G vboxusers cuckoo``
    3) ``cd /home/cuckoo``
    4) ``su cuckoo``
    5) ``python -m virtualenv cuckoo``
    6) ``source /home/cuckoo/cuckoo/bin/activate``
    7) ``pip install -U pip setuptools psycopg2 pycrypto pydeep distorm3 cuckoo weasyprint==0.36 m2crypto``
    8) ``cuckoo && cuckoo community ``

- Database install:

    1) ``apt install mongodb postgresql libpq-dev -y``
        ```python 
            #download Elasticsearch 5.6.8
            usermod -a -G vboxusers cuckoo
            gdebi elasticsearch-
         ```
    2) ``usermod -a -G elasticsearch cuckoo``
    3) edit text:
        ```python   
        #leafpad /etc/elasticsearch/elasticsearch.yml
        cluster.name: es-cuckoo 
        node.name: es-node-n1
        bootstrap.mlockall: true
        network.bind_host: 0.0.0.0
        ```
    4) if you have elasticsearch issues:
         ```python   
            ln -s /etc/elasticsearch /usr/share/elasticsearch/config
            chown -R elasticsearch:elasticsearch /var/lib/elasticsearch
            chown -R elasticsearch:elasticsearch /var/run/elasticsearch
            chown -R elasticsearch:elasticsearch /etc/elasticsearch
         ```
    5) ``service elasticsearch start ``
        ```python 
           curl -X PUT -d @'/home/cuckoo/.cuckoo/elasticsearch/template.json' 'http://0.0.0.0:9200/_template/cuckoo'
         ```
    6) postgresql user, db create:
         ```python 
           echo "CREATE USER cuckoo WITH PASSWORD 'cuckoo';" | sudo -u postgres psql
           echo "CREATE DATABASE cuckoo;" | sudo -u postgres psql
           echo "GRANT ALL PRIVILEGES ON DATABASE cuckoo to cuckoo;" | sudo -u postgres psql
         ```

- TCPDUMP:
    ```python 
      #Tcpdump requires root privileges, but since you don’t want Cuckoo to run as root you’ll have to set specific Linux capabilities to the binary
      setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump && getcap /usr/sbin/tcpdump
    ```
         
- SSDeep:
    1)  ```python 
           cd /root/Downloads/ && git clone https://github.com/bunzen/pySSDeep.git
           cd pySSDeep && python setup.py build && python setup.py install
         ```
- Yara:
    1) `` apt install dh-autoreconf flex bison libjansson-dev libmagic-dev -y ``
    2) `` cd /root/Downloads/ && wget https://github.com/VirusTotal/yara/archive/v3.7.1.tar.gz ``
    3) ``tar -zxf v3.7.1.tar.gz && cd yara-3.7.1/``
    4) ``./bootstrap.sh && ./configure --with-crypto --enable-cuckoo --enable-magic``
    5) ``   make && make install ``
    
- VMCloak:
    ```javascript
    apt install libyaml-dev libpython2.7-dev genisoimage -y
    cd /root/Downloads/ && git clone -b vrde https://github.com/tweemeterjop/vmcloak.git
    cd vmcloak/ && /home/cuckoo/.cuckoo/agent/agent.py vmcloak/data/bootstrap/
    mkdir -p /mnt/win7
    mount -o loop,ro  /root/Downloads/YOUR-ISO /mnt/win7/

    vmcloak-vboxnet0
    vmcloak-iptables 192.168.56.0/24 ens160
    vmcloak init --vrde --resolution 1280x1024 --ramsize 2096 --win7x86 --cpus 2 win7_86 -v -d
    vmcloak install --vrde win7_86 python27 pillow adobepdf chrome cuteftp dotnet40 flash java silverlight vcredist wic -d
    vmcloak snapshot win7_86 win7_86node1 192.168.56.101 -d
    cuckoo machine --add win7_86node1 192.168.56.101 --platform windows --snapshot vmcloak
    cuckoo machine --delete cuckoo1
    ```

- Volatility:
    ```python
    pip install openpyxl ujson pycrypto pytz
    git clone https://github.com/volatilityfoundation/volatility.git
    cd volatility && python setup.py build && python setup.py install
    python vol.py -h

    cp -r /usr/lib/python2.7/dist-packages/volatility* /home/cuckoo/cuckoo/lib/python2.7/site-packages
    chown cuckoo:cuckoo /home/cuckoo/cuckoo/lib/python2.7/site-packages/*
    ```

- MitMproxy:
    ```python
    pip3 install mitmproxy && mitmproxy
    cp ~/.mitmproxy/mitmproxy-ca-cert.p12 /home/cuckoo/.cuckoo/analyzer/windows/bin/cert.p12
    chown cuckoo:cuckoo /home/cuckoo/.cuckoo/analyzer/windows/bin/cert.p12
    ```

- Suricata:
    ```python
    apt update && apt install suricata -y
    echo "alert http any any -> any any (msg:\"FILE store all\"; filestore; noalert; sid:15; rev:1;)"  | sudo tee /etc/suricata/rules/cuckoo.rules
    touch /etc/suricata/suricata-cuckoo.yaml

    # you can find conf in this repo suricata-cuckoo.yaml
    leafpad /etc/suricata/suricata-cuckoo.yaml

    sudo mkdir /var/run/suricata
    sudo chown cuckoo:cuckoo /var/run/suricata
    sudo chown -R cuckoo:cuckoo /etc/suricata
    sudo chown -R cuckoo:cuckoo /var/log/suricata
    sudo touch /etc/suricata/threshold.config

    ```

- Snort:
    ```python
    apt update && apt install snort -y
    ```

- Moloch:
    ```python
    apt-get install wget curl libpcre3-dev uuid-dev libmagic-dev pkg-config g++ flex bison zlib1g-dev libffi-dev gettext libgeoip-dev make libjson-perl libbz2-dev libwww-perl libpng-dev xz-utils libffi-dev
    gdebi moloch_0.50.0-1_amd64.deb

    /data/moloch/bin/Configure
    ### setup: vboxnet0
    ### setup: no
    /data/moloch/db/db.pl http://0.0.0.0:9200 init
    /data/moloch/bin/moloch_add_user.sh cuckoo cuckoo cuckoosandbox --admin
    ```

- InetSim:
    ```python
    echo "deb http://www.inetsim.org/debian/ binary/" > /etc/apt/sources.list.d/inetsim.list
    wget -O - http://www.inetsim.org/inetsim-archive-signing-key.asc | apt-key add -
    apt update && apt install inetsim -y

    ###leafpad /etc/inetsim/inetsim.conf

    #start_service http
    #start_service https

    ```
- ClamAV:
    ```python
    apt-get install clamav

    ### Download signature database from url
    sigtool -u main.cvd

    git clone https://github.com/kojibhy/cuckoo-yara-auto
    python cuckoo-yara-auto/clamav_to_yara.py -f main.ndb -o /home/cuckoo/.cuckoo/yara/calmav.yara
    python3 -m pip install -r cuckoo-yara-auto/requirements.txt && python3 cuckoo-yara-auto/yara-rules.py -d /home/cuckoo/.cuckoo/yara

    ```

- Cuckoo-SandBox-Configs:
    ```python
    all configs are in dir conf
    ```

- Cuckoo-SandBox-Run:
    ```python
    vboxmanage hostonlyif create
    vboxmanage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1

    ## if you want internet inside vbox:

        iptables -A FORWARD -o eth0 -i vboxnet0 -s 192.168.56.0/24 -m conntrack --ctstate NEW -j ACCEPT
        iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        iptables -A POSTROUTING -t nat -j MASQUERADE
        sysctl -w net.ipv4.ip_forward=1

    ##
    service elasticsearch start
    service mongodb start
    systemctl start molochcapture.service
    systemctl start molochviewer.service

    cd /home/cuckoo && su cuckoo

    source cuckoo/bin/activate
    cuckoo web&
    cuckoo -d
    ```
