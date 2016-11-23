---

# MyData SDK Components
This is a part of MyData-SDK implementation of MyData Architecture.

Components are split to their own folders

- [ MyData Account ](/Account/)
- [ Operator Components ](/Operator_Components/)
- [ Service Components ](/Service_Components/)
- [ Service Mockup ](/Service_Mockup/)

## Prerequisites
- [Flask](http://flask.pocoo.org/)
- [Flask-RESTful](http://flask-restful.readthedocs.org/)

## Simple Consent-flow demo

Note:
These instructions have been tested with Linux.
You need to have [Docker](https://www.docker.com/products/overview#/install_the_platform), [Docker Compose](https://docs.docker.com/compose/), [Python](https://www.python.org/) and [Requests -library](http://docs.python-requests.org/) for Python installed.

Clone the repo and start the Docker Compose stack:
```
git clone https://github.com/HIIT/mydata-sdk
cd mydata-sdk
sudo sh start.sh  # Needed to run root only if you haven't configured a docker group for your system
```

Wait until Docker Compose stack has properly started. Last message should be
```
mysql-db                  | Version: '5.6.34'  socket: '/var/run/mysqld/mysqld.sock'  port: 3306  MySQL Community Server (GPL)
```

Now open another terminal and run the ui_flow.py
```
python ui_flow.py
```


## Deployment

Deployment instructions for each component can be found from module's documentation.

Note: If you use [Docker](https://www.docker.com/products/overview#/install_the_platform) and [Docker-Compose](https://docs.docker.com/compose/) see `docker-compose.yml` for details about the stack.

## Documentation

Documentation is available for each component in their respective folders.

## Support / Contact / Contribution
[MyData Architecture](https://github.com/HIIT/mydata-stack)

## Copying and License
This code is licensed under [MIT License](LICENSE)
