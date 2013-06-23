<?php
/*************************************************************************************
 * nginx.php
 * ------
 * Author: Windows Remote Service (support@remotehelp.pp.ua)
 * Copyright: (c) Windows Remote Service (http://remotehelp.pp.ua)
 * Release Version: 1.0.8.11
 * Date Started: 2013/01/15
 *
 * nginx language file for GeSHi-1.0.8.11.
 *
 * Original release found at http://remotehelp.pp.ua
 *
 * CHANGES
 * -------
 * 2013/01/15
 *   - First Release
 * -------------------------
 *
 *************************************************************************************
 *
 *     This file is part of GeSHi.
 *
 *   GeSHi is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   GeSHi is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with GeSHi; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 ************************************************************************************/

$language_data = array (
    'LANG_NAME' => 'nginx',
    'COMMENT_SINGLE' => array(1 => '#'),
    'COMMENT_MULTI' => array(),
    'CASE_KEYWORDS' => GESHI_CAPS_NO_CHANGE,
    'QUOTEMARKS' => array("'", '"'),
    'ESCAPE_CHAR' => '\\',
    'KEYWORDS' => array(
        1 => array(
            // http://wiki.nginx.org/CoreModule
            // http://nginx.org/ru/docs/ngx_core_module.html
            'accept_mutex', 
            'accept_mutex_delay', 
            'daemon', 
            'debug_connection', 
            'debug_points', 
            'error_log', 
            'env', 
            'events', 
            'include', 
            'lock_file', 
            'master_process', 
            'multi_accept', 
            'pcre_jit', 
            'pid', 
            'ssl_engine', 
            'timer_resolution', 
            'use', 
            'user', 
            'worker_aio_requests', 
            'worker_connections', 
            'worker_cpu_affinity', 
            'worker_priority', 
            'worker_processes', 
            'worker_rlimit_core', 
            'worker_rlimit_nofile', 
            'worker_rlimit_sigpending', 
            'working_directory'
            ),
        2 => array(
            // http://wiki.nginx.org/HttpCoreModule
            // http://nginx.org/ru/docs/http/ngx_http_core_module.html
            'aio', 
            'alias', 
            'chunked_transfer_encoding', 
            'client_body_buffer_size', 
            'client_body_in_file_only', 
            'client_body_in_single_buffer', 
            'client_body_temp_path', 
            'client_body_timeout', 
            'client_header_buffer_size', 
            'client_header_timeout', 
            'client_max_body_size', 
            'connection_pool_size', 
            'default_type', 
            'directio', 
            'directio_alignment', 
            'disable_symlinks', 
            'error_page', 
            'etag', 
            'http', 
            'if_modified_since', 
            'ignore_invalid_headers', 
            'internal', 
            'keepalive_disable', 
            'keepalive_requests', 
            'keepalive_timeout', 
            'large_client_header_buffers', 
            'limit_except', 
            'limit_rate', 
            'limit_rate_after', 
            'lingering_close', 
            'lingering_time', 
            'lingering_timeout', 
            'listen', 
            'location', 
            'log_not_found', 
            'log_subrequest', 
            'max_ranges', 
            'merge_slashes', 
            'msie_padding', 
            'msie_refresh', 
            'open_file_cache', 
            'open_file_cache_errors', 
            'open_file_cache_min_uses', 
            'open_file_cache_valid', 
            'optimize_server_names', 
            'port_in_redirect', 
            'postpone_output', 
            'read_ahead', 
            'recursive_error_pages', 
            'request_pool_size', 
            'reset_timedout_connection', 
            'resolver', 
            'resolver_timeout', 
            'root', 
            'satisfy', 
            'satisfy_any', 
            'send_lowat', 
            'send_timeout', 
            'sendfile', 
            'sendfile_max_chunk', 
            'server', 
            'server_name', 
            'server_name_in_redirect', 
            'server_names_hash_bucket_size', 
            'server_names_hash_max_size', 
            'server_tokens', 
            'tcp_nodelay', 
            'tcp_nopush', 
            'try_files', 
            'types', 
            'types_hash_bucket_size', 
            'types_hash_max_size', 
            'underscores_in_headers', 
            'variables_hash_bucket_size', 
            'variables_hash_max_size'
            ),
        3 => array(
            // http://nginx.org/ru/docs/http/ngx_http_access_module.html
            'allow', 
            'deny'
            ),
        4 => array(
            // http://nginx.org/ru/docs/http/ngx_http_addition_module.html
            'add_before_body', 
            'add_after_body', 
            'addition_types'
            ),
        5 => array(
            // http://nginx.org/ru/docs/http/ngx_http_auth_basic_module.html
            'auth_basic', 
            'auth_basic_user_file'
            ),
        6 => array(
            // http://nginx.org/ru/docs/http/ngx_http_autoindex_module.html
            'autoindex', 
            'autoindex_exact_size', 
            'autoindex_localtime'
            ),
        7 => array(
            // http://nginx.org/ru/docs/http/ngx_http_browser_module.html
            'ancient_browser', 
            'ancient_browser_value', 
            'modern_browser', 
            'modern_browser_value'
            ),
        8 => array(
            // http://nginx.org/ru/docs/http/ngx_http_charset_module.html
            'charset', 
            'charset_map', 
            'charset_types', 
            'override_charset', 
            'source_charset'
            ),
        9 => array(
            // http://nginx.org/ru/docs/http/ngx_http_dav_module.html
            'dav_access', 
            'dav_methods', 
            'create_full_put_path', 
            'min_delete_depth'
            ),
        10 => array(
            // http://nginx.org/ru/docs/http/ngx_http_empty_gif_module.html
            'empty_gif',
            ),
        11 => array(
            // http://nginx.org/ru/docs/http/ngx_http_fastcgi_module.html
            'fastcgi_bind', 
            'fastcgi_buffer_size', 
            'fastcgi_buffers', 
            'fastcgi_busy_buffers_size', 
            'fastcgi_cache', 
            'fastcgi_cache_bypass', 
            'fastcgi_cache_key', 
            'fastcgi_cache_lock', 
            'fastcgi_cache_lock_timeout', 
            'fastcgi_cache_methods', 
            'fastcgi_cache_min_uses', 
            'fastcgi_cache_path', 
            'fastcgi_cache_use_stale', 
            'fastcgi_cache_valid', 
            'fastcgi_connect_timeout', 
            'fastcgi_hide_header', 
            'fastcgi_ignore_client_abort', 
            'fastcgi_ignore_headers', 
            'fastcgi_index', 
            'fastcgi_intercept_errors', 
            'fastcgi_keep_conn', 
            'fastcgi_max_temp_file_size', 
            'fastcgi_next_upstream', 
            'fastcgi_no_cache', 
            'fastcgi_param', 
            'fastcgi_pass', 
            'fastcgi_pass_header', 
            'fastcgi_read_timeout', 
            'fastcgi_pass_request_body', 
            'fastcgi_pass_request_headers', 
            'fastcgi_send_lowat', 
            'fastcgi_send_timeout', 
            'fastcgi_split_path_info', 
            'fastcgi_store', 
            'fastcgi_store_access', 
            'fastcgi_temp_file_write_size', 
            'fastcgi_temp_path'
            ),
        12 => array(
            // http://nginx.org/ru/docs/http/ngx_http_flv_module.html
            'flv'
            ),
        13 => array(
            // http://nginx.org/ru/docs/http/ngx_http_geo_module.html
            'geo'
            ),
        14 => array(
            // http://nginx.org/ru/docs/http/ngx_http_geoip_module.html
            'geoip_country', 
            'geoip_city', 
            'geoip_org', 
            'geoip_proxy', 
            'geoip_proxy_recursive'
            ),
        15 => array(
            // http://nginx.org/ru/docs/http/ngx_http_gunzip_module.html
            'gunzip', 
            'gunzip_buffers'
            ),
        16 => array(
            // http://nginx.org/ru/docs/http/ngx_http_gzip_module.html
            'gzip', 
            'gzip_buffers', 
            'gzip_comp_level', 
            'gzip_disable', 
            'gzip_min_length', 
            'gzip_http_version', 
            'gzip_proxied', 
            'gzip_types', 
            'gzip_vary'
            ),
        17 => array(
            // http://nginx.org/ru/docs/http/ngx_http_gzip_static_module.html
            'gzip_static'
            ),
        18 => array(
            // http://nginx.org/ru/docs/http/ngx_http_headers_module.html
            'add_header', 
            'expires'
            ),
        19 => array(
            // http://nginx.org/ru/docs/http/ngx_http_image_filter_module.html
            'image_filter', 
            'image_filter_buffer', 
            'image_filter_jpeg_quality', 
            'image_filter_sharpen', 
            'image_filter_transparency'
            ),
        20 => array(
            // http://nginx.org/ru/docs/http/ngx_http_index_module.html
            'index'
            ),
        21 => array(
            // http://nginx.org/ru/docs/http/ngx_http_limit_conn_module.html
            'limit_conn', 
            'limit_conn_log_level', 
            'limit_conn_zone', 
            'limit_zone'
            ),
        22 => array(
            // http://nginx.org/ru/docs/http/ngx_http_limit_req_module.html
            'limit_req', 
            'limit_req_log_level', 
            'limit_req_zone'
            ),
        23 => array(
            // http://nginx.org/ru/docs/http/ngx_http_log_module.html
            'access_log', 
            'log_format', 
            'open_log_file_cache'
            ),
        24 => array(
            // http://nginx.org/ru/docs/http/ngx_http_map_module.html
            'map', 
            'map_hash_bucket_size', 
            'map_hash_max_size'
            ),
        25 => array(
            // http://nginx.org/ru/docs/http/ngx_http_memcached_module.html
            'memcached_bind', 
            'memcached_buffer_size', 
            'memcached_connect_timeout', 
            'memcached_gzip_flag', 
            'memcached_next_upstream', 
            'memcached_pass', 
            'memcached_read_timeout', 
            'memcached_send_timeout'
            ),
        26 => array(
            // http://nginx.org/ru/docs/http/ngx_http_mp4_module.html
            'mp4', 
            'mp4_buffer_size', 
            'mp4_max_buffer_size'
            ),
        27 => array(
            // http://nginx.org/ru/docs/http/ngx_http_perl_module.html
            'perl', 
            'perl_modules', 
            'perl_require', 
            'perl_set'
            ),
        28 => array(
            // http://nginx.org/ru/docs/http/ngx_http_proxy_module.html
            'proxy_bind', 
            'proxy_buffer_size', 
            'proxy_buffering', 
            'proxy_buffers', 
            'proxy_busy_buffers_size', 
            'proxy_cache', 
            'proxy_cache_bypass', 
            'proxy_cache_key', 
            'proxy_cache_lock', 
            'proxy_cache_lock_timeout', 
            'proxy_cache_methods', 
            'proxy_cache_min_uses', 
            'proxy_cache_path', 
            'proxy_cache_use_stale', 
            'proxy_cache_valid', 
            'proxy_connect_timeout', 
            'proxy_cookie_domain', 
            'proxy_cookie_path', 
            'proxy_headers_hash_bucket_size', 
            'proxy_headers_hash_max_size', 
            'proxy_hide_header', 
            'proxy_http_version', 
            'proxy_ignore_client_abort', 
            'proxy_ignore_headers', 
            'proxy_intercept_errors', 
            'proxy_max_temp_file_size', 
            'proxy_method', 
            'proxy_next_upstream', 
            'proxy_no_cache', 
            'proxy_pass', 
            'proxy_pass_header', 
            'proxy_read_timeout', 
            'proxy_pass_request_body', 
            'proxy_pass_request_headers', 
            'proxy_redirect', 
            'proxy_send_lowat', 
            'proxy_send_timeout', 
            'proxy_set_body', 
            'proxy_set_header', 
            'proxy_ssl_session_reuse', 
            'proxy_store', 
            'proxy_store_access', 
            'proxy_temp_file_write_size', 
            'proxy_temp_path'
            ),
        29 => array(
            // http://nginx.org/ru/docs/http/ngx_http_random_index_module.html
            'random_index',
            ),
        30 => array(
            // http://nginx.org/ru/docs/http/ngx_http_realip_module.html
            'set_real_ip_from', 
            'real_ip_header', 
            'real_ip_recursive'
            ),
        31 => array(
            // http://nginx.org/ru/docs/http/ngx_http_referer_module.html
            'referer_hash_bucket_size', 
            'referer_hash_max_size', 
            'valid_referers'
            ),
        32 => array(
            // http://nginx.org/ru/docs/http/ngx_http_rewrite_module.html
            'break', 
            'if', 
            'return', 
            'rewrite', 
            'rewrite_log', 
            'set', 
            'uninitialized_variable_warn'
            ),
        33 => array(
            // http://nginx.org/ru/docs/http/ngx_http_secure_link_module.html
            'secure_link_secret'
            ),
        34 => array(
            // http://nginx.org/ru/docs/http/ngx_http_split_clients_module.html
            'split_clients',
            ),
        35 => array(
            // http://nginx.org/ru/docs/http/ngx_http_ssi_module.html
            'ssi', 
            'ssi_min_file_chunk', 
            'ssi_silent_errors', 
            'ssi_types', 
            'ssi_value_length'
            ),
        36 => array(
            // http://nginx.org/ru/docs/http/ngx_http_ssl_module.html
            'ssl', 
            'ssl_certificate', 
            'ssl_certificate_key', 
            'ssl_ciphers', 
            'ssl_client_certificate', 
            'ssl_crl', 
            'ssl_dhparam', 
            'ssl_prefer_server_ciphers', 
            'ssl_protocols', 
            'ssl_session_cache', 
            'ssl_session_timeout', 
            'ssl_stapling', 
            'ssl_stapling_file', 
            'ssl_stapling_responder', 
            'ssl_stapling_verify', 
            'ssl_trusted_certificate', 
            'ssl_verify_client', 
            'ssl_verify_depth'
            ),
        37 => array(
            // http://nginx.org/ru/docs/http/ngx_http_sub_module.html
            'sub_filter', 
            'sub_filter_once', 
            'sub_filter_types'
            ),
        38 => array(
            // http://nginx.org/ru/docs/http/ngx_http_upstream_module.html
            'upstream', 
            'server', 
            'ip_hash', 
            'keepalive', 
            'least_conn'
            ),
        39 => array(
            // http://nginx.org/ru/docs/http/ngx_http_userid_module.html
            'userid', 
            'userid_domain', 
            'userid_expires', 
            'userid_mark', 
            'userid_name', 
            'userid_p3p', 
            'userid_path', 
            'userid_service'
            ),
        40 => array(
            // http://nginx.org/ru/docs/http/ngx_http_xslt_module.html
            'xml_entities', 
            'xslt_param', 
            'xslt_string_param', 
            'xslt_stylesheet', 
            'xslt_types'
            ),
        41 => array(
            // http://nginx.org/ru/docs/mail/ngx_mail_core_module.html
            'listen', 
            'mail', 
            'protocol', 
            'server', 
            'server_name', 
            'so_keepalive', 
            'timeout'
            ),
        42 => array(
            // http://nginx.org/ru/docs/mail/ngx_mail_pop3_module.html
            'pop3_auth', 
            'pop3_capabilities'
            ),
        43 => array(
            // http://nginx.org/ru/docs/mail/ngx_mail_imap_module.html
            'imap_auth', 
            'imap_capabilities', 
            'imap_client_buffer'
            ),
        44 => array(
            // http://nginx.org/ru/docs/mail/ngx_mail_smtp_module.html
            'smtp_auth', 
            'smtp_capabilities'
            ),
        45 => array(
            // http://nginx.org/ru/docs/mail/ngx_mail_auth_http_module.html
            'auth_http', 
            'auth_http_header', 
            'auth_http_timeout'
            ),
        46 => array(
            // http://nginx.org/ru/docs/mail/ngx_mail_proxy_module.html
            'proxy_buffer', 
            'proxy_pass_error_message', 
            'proxy_timeout', 
            'xclient'
            ),
        47 => array(
            // http://nginx.org/ru/docs/mail/ngx_mail_ssl_module.html
            'ssl', 
            'ssl_certificate', 
            'ssl_certificate_key', 
            'ssl_prefer_server_ciphers', 
            'ssl_protocols', 
            'ssl_session_cache', 
            'ssl_session_timeout', 
            'starttls'
            ),
        48 => array(
            // http://wiki.nginx.org/HttpUwsgiModule
            'uwsgi_bind',
            'uwsgi_buffer_size',
            'uwsgi_buffering',
            'uwsgi_buffers',
            'uwsgi_busy_buffers_size',
            'uwsgi_cache',
            'uwsgi_cache_bypass',
            'uwsgi_cache_key',
            'uwsgi_cache_lock',
            'uwsgi_cache_lock_timeout',
            'uwsgi_cache_methods',
            'uwsgi_cache_min_uses',
            'uwsgi_cache_path',
            'uwsgi_cache_use_stale',
            'uwsgi_cache_valid',
            'uwsgi_connect_timeout',
            'uwsgi_hide_header',
            'uwsgi_ignore_client_abort',
            'uwsgi_ignore_headers',
            'uwsgi_intercept_errors',
            'uwsgi_max_temp_file_size',
            'uwsgi_modifier',
            'uwsgi_next_upstream',
            'uwsgi_no_cache',
            'uwsgi_param',
            'uwsgi_pass',
            'uwsgi_pass_header',
            'uwsgi_pass_request_body',
            'uwsgi_pass_request_headers',
            'uwsgi_read_timeout',
            'uwsgi_send_timeout',
            'uwsgi_store',
            'uwsgi_store_access',
            'uwsgi_string',
            'uwsgi_temp_file_write_size',
            'uwsgi_temp_path'
            ),
        49 => array(
            // http://wiki.nginx.org/HttpScgiModule
            // Note: These directives were pulled from nginx 1.2.3
            //       ngx_http_scgi_module.c source file.
            'scgi_bind',
            'scgi_buffering',
            'scgi_buffers',
            'scgi_buffer_size',
            'scgi_busy_buffers_size',
            'scgi_cache',
            'scgi_cache_bypass',
            'scgi_cache_key',
            'scgi_cache_lock',
            'scgi_cache_lock_timeout',
            'scgi_cache_methods',
            'scgi_cache_min_uses',
            'scgi_cache_path',
            'scgi_cache_use_stale',
            'scgi_cache_valid',
            'scgi_connect_timeout',
            'scgi_hide_header',
            'scgi_ignore_client_abort',
            'scgi_ignore_headers',
            'scgi_intercept_errors',
            'scgi_max_temp_file_size',
            'scgi_next_upstream',
            'scgi_no_cache',
            'scgi_param',
            'scgi_pass',
            'scgi_pass_header',
            'scgi_pass_request_body',
            'scgi_pass_request_headers',
            'scgi_read_timeout',
            'scgi_send_timeout',
            'scgi_store',
            'scgi_store_access',
            'scgi_temp_file_write_size',
            'scgi_temp_path'
            ),
        50 => array(
            // http://wiki.nginx.org/X-accel
            'X-Accel-Redirect',
            'X-Accel-Buffering',
            'X-Accel-Charset',
            'X-Accel-Expires',
            'X-Accel-Limit-Rate'
            ),
        51 => array(
            // http://wiki.nginx.org/GooglePerftoolsModule
            'google_perftools_profiles'
            ),
        ),
    'SYMBOLS' => array(
            '{', '}', '(', ')', '~', '=', ';'
        ),
    'CASE_SENSITIVE' => array(
        GESHI_COMMENTS => true,
        1 => true,
        2 => true,
        3 => true,
        4 => true,
        5 => true,
        6 => true,
        7 => true,
        8 => true,
        9 => true,
        10 => true,
        11 => true,
        12 => true,
        13 => true,
        14 => true,
        15 => true,
        16 => true,
        17 => true,
        18 => true,
        19 => true,
        20 => true,
        21 => true,
        22 => true,
        23 => true,
        24 => true,
        25 => true,
        26 => true,
        27 => true,
        28 => true,
        29 => true,
        30 => true,
        31 => true,
        32 => true,
        33 => true,
        34 => true,
        35 => true,
        36 => true,
        37 => true,
        38 => true,
        39 => true,
        40 => true,
        41 => true,
        42 => true,
        43 => true,
        44 => true,
        45 => true,
        46 => true,
        47 => true,
        48 => true,
        49 => true,
        50 => true,
        51 => true,
        ),
    'STYLES' => array(
        'KEYWORDS' => array(
            1 => 'color: #b1b100;',
            2 => 'color: #000000; font-weight: bold;',
            3 => 'color: #000066;',
            4 => 'color: #993333;'
            ),
        'COMMENTS' => array(
            1 => 'color: #808080; font-style: italic;',
            ),
        'ESCAPE_CHAR' => array(
            0 => 'color: #000099; font-weight: bold;'
            ),
        'BRACKETS' => array(
            0 => 'color: #66cc66;'
            ),
        'STRINGS' => array(
            0 => 'color: #ff0000;'
            ),
        'NUMBERS' => array(
            0 => 'color: #cc66cc;'
            ),
        'METHODS' => array(
            1 => 'color: #202020;',
            2 => 'color: #202020;'
            ),
        'SYMBOLS' => array(
            0 => 'color: #66cc66;'
            ),
        'REGEXPS' => array(
            0 => 'color: #000066;',
            4 => 'color: #000000; font-weight: bold;'
            ),
        'SCRIPT' => array()
        ),
    'URLS' => array(
        1 => 'http://nginx.org/ru/docs/ngx_core_module.html#{FNAME}', 
        2 => 'http://nginx.org/ru/docs/http/ngx_http_core_module.html#{FNAME}', 
        3 => 'http://nginx.org/ru/docs/http/ngx_http_access_module.html#{FNAME}', 
        4 => 'http://nginx.org/ru/docs/http/ngx_http_addition_module.html#{FNAME}', 
        5 => 'http://nginx.org/ru/docs/http/ngx_http_auth_basic_module.html#{FNAME}', 
        6 => 'http://nginx.org/ru/docs/http/ngx_http_autoindex_module.html#{FNAME}', 
        7 => 'http://nginx.org/ru/docs/http/ngx_http_browser_module.html#{FNAME}', 
        8 => 'http://nginx.org/ru/docs/http/ngx_http_charset_module.html#{FNAME}', 
        9 => 'http://nginx.org/ru/docs/http/ngx_http_dav_module.html#{FNAME}', 
        10 => 'http://nginx.org/ru/docs/http/ngx_http_empty_gif_module.html#{FNAME}', 
        11 => 'http://nginx.org/ru/docs/http/ngx_http_fastcgi_module.html#{FNAME}', 
        12 => 'http://nginx.org/ru/docs/http/ngx_http_flv_module.html#{FNAME}', 
        13 => 'http://nginx.org/ru/docs/http/ngx_http_geo_module.html#{FNAME}', 
        14 => 'http://nginx.org/ru/docs/http/ngx_http_geoip_module.html#{FNAME}', 
        15 => 'http://nginx.org/ru/docs/http/ngx_http_gunzip_module.html#{FNAME}', 
        16 => 'http://nginx.org/ru/docs/http/ngx_http_gzip_module.html#{FNAME}', 
        17 => 'http://nginx.org/ru/docs/http/ngx_http_gzip_static_module.html#{FNAME}', 
        18 => 'http://nginx.org/ru/docs/http/ngx_http_headers_module.html#{FNAME}', 
        19 => 'http://nginx.org/ru/docs/http/ngx_http_image_filter_module.html#{FNAME}', 
        20 => 'http://nginx.org/ru/docs/http/ngx_http_index_module.html#{FNAME}', 
        21 => 'http://nginx.org/ru/docs/http/ngx_http_limit_conn_module.html#{FNAME}', 
        22 => 'http://nginx.org/ru/docs/http/ngx_http_limit_req_module.html#{FNAME}', 
        23 => 'http://nginx.org/ru/docs/http/ngx_http_log_module.html#{FNAME}', 
        24 => 'http://nginx.org/ru/docs/http/ngx_http_map_module.html#{FNAME}', 
        25 => 'http://nginx.org/ru/docs/http/ngx_http_memcached_module.html#{FNAME}', 
        26 => 'http://nginx.org/ru/docs/http/ngx_http_mp4_module.html#{FNAME}', 
        27 => 'http://nginx.org/ru/docs/http/ngx_http_perl_module.html#{FNAME}', 
        28 => 'http://nginx.org/ru/docs/http/ngx_http_proxy_module.html#{FNAME}', 
        29 => 'http://nginx.org/ru/docs/http/ngx_http_random_index_module.html#{FNAME}', 
        30 => 'http://nginx.org/ru/docs/http/ngx_http_realip_module.html#{FNAME}', 
        31 => 'http://nginx.org/ru/docs/http/ngx_http_referer_module.html#{FNAME}', 
        32 => 'http://nginx.org/ru/docs/http/ngx_http_rewrite_module.html#{FNAME}', 
        33 => 'http://nginx.org/ru/docs/http/ngx_http_secure_link_module.html#{FNAME}', 
        34 => 'http://nginx.org/ru/docs/http/ngx_http_split_clients_module.html#{FNAME}', 
        35 => 'http://nginx.org/ru/docs/http/ngx_http_ssi_module.html#{FNAME}', 
        36 => 'http://nginx.org/ru/docs/http/ngx_http_ssl_module.html#{FNAME}', 
        37 => 'http://nginx.org/ru/docs/http/ngx_http_sub_module.html#{FNAME}', 
        38 => 'http://nginx.org/ru/docs/http/ngx_http_upstream_module.html#{FNAME}', 
        39 => 'http://nginx.org/ru/docs/http/ngx_http_userid_module.html#{FNAME}', 
        40 => 'http://nginx.org/ru/docs/http/ngx_http_xslt_module.html#{FNAME}', 
        41 => 'http://nginx.org/ru/docs/mail/ngx_mail_core_module.html#{FNAME}', 
        42 => 'http://nginx.org/ru/docs/mail/ngx_mail_pop3_module.html#{FNAME}', 
        43 => 'http://nginx.org/ru/docs/mail/ngx_mail_imap_module.html#{FNAME}', 
        44 => 'http://nginx.org/ru/docs/mail/ngx_mail_smtp_module.html#{FNAME}', 
        45 => 'http://nginx.org/ru/docs/mail/ngx_mail_auth_http_module.html#{FNAME}', 
        46 => 'http://nginx.org/ru/docs/mail/ngx_mail_proxy_module.html#{FNAME}', 
        47 => 'http://nginx.org/ru/docs/mail/ngx_mail_ssl_module.html#{FNAME}', 
        48 => 'http://wiki.nginx.org/HttpUwsgiModule#{FNAME}', 
        49 => 'http://wiki.nginx.org/HttpScgiModule#{FNAME}', 
        50 => 'http://wiki.nginx.org/X-accel#{FNAME}', 
        51 => 'http://wiki.nginx.org/GooglePerftoolsModule#{FNAME}'
        ),
    'OOLANG' => true,
    'OBJECT_SPLITTERS' => array(),
    'REGEXPS' => array(
        0 => '[\\$%@]+[a-zA-Z_][a-zA-Z0-9_]*',
        4 => '&lt;[a-zA-Z_][a-zA-Z0-9_]*&gt;',
        ),
    'STRICT_MODE_APPLIES' => GESHI_MAYBE,
    'SCRIPT_DELIMITERS' => array(),
    'HIGHLIGHT_STRICT_BLOCK' => array(),
    // 'PARSER_CONTROL' => array(
        // // Если нужно отключить подсветку брэкетов и символов, 
        // // то снимаем комментарии с массива ENABLE_FLAGS
        // 'ENABLE_FLAGS' => array(
            // 'BRACKETS' => GESHI_NEVER,
            // 'SYMBOLS' => GESHI_NEVER
        // ),
        // // Исключения парсинга для KEYWORDS ключевых слов
        // 'KEYWORDS' => array(
            // 5 => array(
                // // Отключаем подсветку некоторых (KEYWORDS) директив
                // 'DISALLOWED_BEFORE' => 'http',
                // 'DISALLOWED_AFTER' => 'http',
            // )
        // )
    // )
);

?>
