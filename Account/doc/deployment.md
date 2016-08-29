# Deployment
Note: Instructions based on Ubuntu 14.04 server


## Prerequisites

### Update package repositories
    sudo apt-get update

### MySQL Database
    sudo apt-get -y install mysql-server-5.6
    sudo mysql_secure_installation
    sudo service mysql restart

### System wide dependencies with apt-get
    sudo apt-get -y install build-essential
    sudo apt-get -y install python
    sudo apt-get -y install libssl-dev
    sudo apt-get -y install libffi-dev
    sudo apt-get -y install python-dev
    sudo apt-get -y install python-pip
    sudo apt-get -y install libmysqlclient-dev
    sudo apt-get -y install git


### System wide dependencies with pip
    sudo pip install virtualenv


## Deployment

### Prepare directories
    sudo mkdir -p /var/www/myDataAccount
    sudo chown -R www-data /var/www/myDataAccount
    sudo chmod 755 -R /var/www
    cd /var/www/myDataAccount

### Clone from Git
Clone this repo.

Checkout master-branch.
    
    cd Account

### Configure

#### MySQL Database
In MySQL shell

    DROP DATABASE MyDataAccount;
    source doc/database/MyDataAccount-DBinit.sql
    CREATE USER '<DATABASE_USER>'@'localhost' IDENTIFIED BY '<DATABASE_USER_PASSWORD>';
    GRANT CREATE TEMPORARY TABLES, DELETE, DROP, INSERT, LOCK TABLES, SELECT, UPDATE ON MyDataAccount.* TO 'mydataaccount'@'localhost';
    FLUSH PRIVILEGES;

#### Flask App config
Check application configuration file and modify if necessary.

    sudo nano config.py

#### Setup virtual environment

    sudo virtualenv venv --no-site-packages
    source venv/bin/activate
    pip install -r requirements.txt
    deactivate



# Run MyData Account Application
## Development mode
Run application in development mode at port 8080

    cd /var/www/myDataAccount/mydata-sdk/Account
    source venv/bin/activate
    python run.py


## Production mode
Run application in production mode at port 80

### Prerequisites

    sudo apt-get update
    sudo apt-get -y install nginx
    sudo pip install uwsgi

### Test uWSGI serving

    cd /var/www/myDataAccount/mydata-sdk/Account
    source venv/bin/activate
    sudo uwsgi --socket 0.0.0.0:8080 --protocol=http -w wsgi --virtualenv venv/ --callable app

Try to access application with web-browser via (http://example.org:8080)

Deactivate virtual environment

    deactivate

### Configure uWSGI

#### uWSGI Configuration File
Modify application path if necessary. At least application's base path should be updated.

    cd /var/www/myDataAccount/mydata-sdk/Account
    sudo nano uwsgi.ini

#### File permissions
Ensure ownership and access rights of application files

    sudo chown www-data -R /var/www/myDataAccount/
    suod chmod 664 -R /var/www/myDataAccount/


#### Start uWSGI serving

    cd /var/www/myDataAccount/mydata-sdk/Account
    sudo uwsgi --ini uwsgi.ini &

### Configure Nginx

#### Delete default config

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
