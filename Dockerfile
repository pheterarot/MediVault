FROM php:8.2-apache
RUN docker-php-ext-install mysqli \
    && a2enmod rewrite headers \
    && sed -i 's/AllowOverride None/AllowOverride All/' /etc/apache2/apache2.conf
COPY . /var/www/html/
