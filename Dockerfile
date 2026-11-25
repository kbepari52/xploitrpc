# Vulnerable WordPress 5.0 lab for validating xploitrpc with ZERO mocks.
#
# The wordpress:5.0.0-php7.2-apache base image supplies PHP 7.2 and Apache,
# but its bundled core in /usr/src/wordpress is patched. We replace that
# source tree with the genuine WordPress 5.0 release from wordpress.org.
# The official entrypoint then copies the vulnerable core into the web root
# on first install, and the named volume keeps it there across restarts.
#
# Apache also listens on 8080 inside the container, matching the published
# host port. The exploit poisons _wp_attached_file with a '?' suffix, which
# forces WordPress to load the source image through its own URL; that URL
# must be reachable from inside the container.
FROM wordpress:5.0.0-php7.2-apache

RUN printf 'Listen 8080\n' >> /etc/apache2/ports.conf \
    && printf '<VirtualHost *:8080>\n\tDocumentRoot /var/www/html\n</VirtualHost>\n' \
       >> /etc/apache2/sites-available/000-default.conf

# Replace the image's patched core source with the real WP 5.0 release.
RUN curl -fsSL https://wordpress.org/wordpress-5.0.tar.gz -o /tmp/wp.tar.gz \
    && rm -rf /usr/src/wordpress \
    && mkdir -p /usr/src/wordpress \
    && tar -xzf /tmp/wp.tar.gz -C /usr/src/wordpress --strip-components=1 \
    && chown -R www-data:www-data /usr/src/wordpress \
    && rm -f /tmp/wp.tar.gz

ENV WP_AUTO_UPDATE_CORE=false

# Must-use plugin that hard-disables all automatic updates. Without this,
# WordPress silently upgrades to 5.0.32 and patches the target CVE.
RUN mkdir -p /usr/src/wordpress/wp-content/mu-plugins \
    && printf '%s\n' "<?php" \
       "add_filter('auto_update_core', '__return_false');" \
       "add_filter('automatic_updater_disabled', '__return_true');" \
       "add_filter('auto_update_plugin', '__return_false');" \
       "add_filter('auto_update_theme', '__return_false');" \
       > /usr/src/wordpress/wp-content/mu-plugins/disable-updates.php \
    && chown -R www-data:www-data /usr/src/wordpress/wp-content/mu-plugins

EXPOSE 80 8080
