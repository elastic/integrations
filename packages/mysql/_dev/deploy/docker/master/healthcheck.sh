#!/bin/bash
# Health check script for MySQL

# Use the MYSQL_ROOT_PASSWORD environment variable or a default password
MYSQL_PWD=${MYSQL_ROOT_PASSWORD:-defaultpassword}

# Check if MySQL is ready
mysqladmin ping -h localhost -u root --silent