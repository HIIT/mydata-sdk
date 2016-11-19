#!/bin/bash
#docker-entrypoint.sh

# Note: This script uses the exec Bash command so that the final running 
# application becomes the container’s PID 1. This allows the application to 
# receive any Unix signals sent to the container. 
# See the ENTRYPOINT help for more details.
# https://docs.docker.com/engine/userguide/eng-image/dockerfile_best-practices/#/entrypoint

# -e  - Exit immediately if a command exits with a non-zero status.
set -e

# Preprocess configuration files based on environment variables given to 
# "docker run" -command or Docker Compose
j2 $APP_INSTALL_PATH/account_config_template.py.j2 > \
   $APP_INSTALL_PATH/config.py

# Try to start whatever was given as a parameter to "docker run" -command
exec "$@"
