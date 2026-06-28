FROM php:8.3-cli AS builder

# Build deps incl libmodsecurity dev
RUN apt-get update && apt-get install -y \
    $PHPIZE_DEPS \
    libmodsecurity-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build/extension
COPY src/php_waf/ ./
# Build the extension
RUN phpize \
    && ./configure --enable-waf --with-modsecurity \
    && make -j$(nproc)

FROM php:8.3-fpm

# Runtime deps
RUN apt-get update && apt-get install -y \
    libmodsecurity3 \
    && rm -rf /var/lib/apt/lists/*

# Copy extension
COPY --from=builder /build/extension/modules/waf.so /usr/local/lib/php/extensions/no-debug-non-zts-20230831/
RUN docker-php-ext-enable waf

# Copy config
COPY src/php_waf/php_waf.ini /usr/local/etc/php/conf.d/zz-waf.ini

RUN mkdir -p /etc/modsecurity

# FPM pool tuning (see e2e/etc/php-fpm.d/zz-pool.conf). Bakes a larger
# pm.max_children into the image so concurrency is not capped at the stock 5.
COPY e2e/etc/php-fpm.d/zz-pool.conf /usr/local/etc/php-fpm.d/zz-pool.conf

# Verify install
RUN php -m | grep waf
