# Deployment
Note: Instructions based on clean Ubuntu 14.04 server


## Prerequisites

### Update package repositories
    sudo apt-get update

### MySQL Database
    sudo apt-get -y install mysql-server-5.6

You will be prompted for prompted to create a root password during the installation. 
These instructions are using 'Y3xUcheg' as root password.

#### Securing MySQL installation
    sudo mysql_secure_installation

#### Finalizing MySQL installation
    sudo service mysql restart

### System wide dependencies with apt-get
    sudo apt-get -y install build-essential
    sudo apt-get -y install libssl-dev
    sudo apt-get -y install libffi-dev
    sudo apt-get -y install python
    sudo apt-get -y install python-dev
    sudo apt-get -y install python-pip
    sudo apt-get -y install libmysqlclient-dev
    sudo apt-get -y install git


### System wide dependencies with pip
    sudo pip install cryptography
    sudo pip install virtualenv


## Deployment

### Prepare directories
    cd ~
    mkdir myDataSDK
    cd myDataSDK

### Clone from Git
    git clone https://github.com/HIIT/mydata-sdk.git

### Configure

    cd mydata-sdk
    cd Account

#### MySQL Database

##### Start mysql shell

    mysql -u root -pY3xUcheg

##### In MySQL shell

    source doc/database/MyDataAccount-DBinit.sql
    source doc/database/MyDataAccount-UserInit.sql

##### Quit from MySQL shell

    quit

#### Flask App config
Check application configuration file and modify if necessary.

    nano config.py

#### Setup virtual environment

    virtualenv venv
    source venv/bin/activate
    ./venv/bin/pip install -r requirements.txt
    deactivate



# Run MyData Account Application
MyData Account can be run in development mode or in production mode.

## Development mode
Run application in development mode at port 8080

    cd ~/myDataSDK/mydata-sdk/Account
    source venv/bin/activate
    python run.py


## Production mode
Run application in production mode at port 80

### Prerequisites

    sudo apt-get update
    sudo apt-get -y install nginx
    sudo pip install uwsgi
    
### Prepare directories
    cd ~/myDataSDK
    sudo mkdir -p /var/www/myDataSDK
    sudo cp -R ./mydata-sdk/ /var/www/myDataSDK
    sudo chown -R www-data /var/www/myDataSDK
    sudo chmod 755 -R /var/www

### Test uWSGI serving

    cd /var/www/myDataSDK/mydata-sdk/Account/
    source venv/bin/activate
    sudo uwsgi --socket 0.0.0.0:8080 --protocol=http -w wsgi --virtualenv venv/ --callable app

Try to access application with web-browser via (http://example.org:8080)

Kill uwsgi process 

    Ctrl + c

Deactivate virtual environment

    deactivate

### Configure uWSGI

#### uWSGI Configuration File
Modify application's base path if necessary.

    sudo nano uwsgi.ini


#### Start uWSGI serving

    sudo uwsgi --ini uwsgi.ini &

### Configure Nginx

#### Delete default config

    sudo rm /etc/nginx/sites-enabled/default
    sudo rm /etc/nginx/sites-available/default

#### Add new configuration file

    sudo nano /etc/nginx/sites-available/mydata-account

Add following content to newly created configuration file and modify if necessary.

    server {
        listen	80;
        server_name	127.0.0.1;
        charset	utf-8;
        client_max_body_size 5M;
        root /var/www/myDataAccount/mydata-sdk/Account;

        location / {
            include uwsgi_params;
            uwsgi_pass 127.0.0.1:9090;
        }
    }


#### Enable new site

    sudo ln -s /etc/nginx/sites-available/mydata-account /etc/nginx/sites-enabled/mydata-account

#### Check Nginx config for syntax errors

    sudo nginx -t


#### Restart Nginx

    sudo service nginx restart

#### Access Account

Access application with web-browser via (http://example.org:80)
