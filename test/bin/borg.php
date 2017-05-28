#!/usr/bin/php
<?php
    $options = getopt('', [
        'config:',
    ]);

    /**
     * @var \NokitaKaze\TestHTTPServer\BorgSettings $settings
     * @var null                                    $this
     */
    $settings = (object) unserialize(file_get_contents($options['config']));

    $stream_context = stream_context_create();
    if (isset($settings->ssl_server_certificate_file)) {
        /* @url http://php.net/manual/en/context.ssl.php */
        // Проверка происходит ниже и руками
        stream_context_set_option($stream_context, 'ssl', 'verify_peer', false);
        stream_context_set_option($stream_context, 'ssl', 'capture_peer_cert', true);
        stream_context_set_option($stream_context, 'ssl', 'capture_peer_cert_chain', true);

        if (isset($settings->ssl_client_certificate_file)) {
            stream_context_set_option($stream_context, 'ssl', 'local_cert',
                $settings->ssl_client_certificate_file);
            if (isset($settings->ssl_client_key_file)) {
                stream_context_set_option($stream_context, 'ssl', 'local_pk',
                    $settings->ssl_client_key_file);
            }
            if (isset($settings->ssl_client_key_password)) {
                stream_context_set_option($stream_context, 'ssl', 'passphrase',
                    $settings->ssl_client_key_password);
            }
        }
    } elseif (isset($settings->ssl_client_key_file)) {
        echo "ssl_client_key_file is set, but ssl_server_certificate_file is missing\n";

        return 1;
    } elseif (isset($settings->ssl_client_key_password)) {
        echo "ssl_client_key_password is set, but ssl_server_certificate_file is missing\n";

        return 1;
    } elseif (isset($settings->ssl_client_certificate_file)) {
        echo "ssl_client_certificate_file is set, but ssl_server_certificate_file is missing\n";

        return 3;
    }

    if (isset($settings->host)) {
        $uri_domain = $settings->host;
    } elseif (isset($settings->domain)) {
        $uri_domain = $settings->domain;
    } else {
        $uri_domain = strtolower(gethostname());
    }

    $uri = sprintf('%s://%s:%d',
        (isset($settings->is_ssl) and $settings->is_ssl) ? 'ssl' : 'tcp',
        $uri_domain,
        $settings->port
    );
    unset($uri_domain);
    $client_socket = stream_socket_client($uri, $errno, $errstr, 3, STREAM_CLIENT_CONNECT, $stream_context);
    if ($client_socket === false) {
        echo 'Can not create socket ['.$errno.']: '.$errstr."\n";

        return 4;
    }

    $scenario = isset($settings->scenario) ? $settings->scenario : 0;
    $domain = isset($settings->domain) ? $settings->domain : strtolower(gethostname());

    if (isset($settings->ssl_server_certificate_file)) {
        $c = openssl_x509_parse(file_get_contents($settings->ssl_server_certificate_file));
        if ($c === false) {
            echo "Intermediate CA file is malformed or can not be used as certificate\n";

            return 8;
        }
        if (!isset($c['extensions'], $c['extensions']['subjectKeyIdentifier'])) {
            echo "Intermediate CA is malformed\n";

            return 9;
        }

        $a = stream_context_get_options($stream_context);
        if (!isset($a['ssl'], $a['ssl']['peer_certificate']) or !is_resource($a['ssl']['peer_certificate'])) {
            echo "Remote server did not promote certificate\n";

            return 10;
        }
        $found = false;
        foreach ($a['ssl']['peer_certificate_chain'] as $certificate_num => &$single_certificate) {
            $b = openssl_x509_parse($single_certificate);
            if (!isset($b['extensions'], $b['extensions']['authorityKeyIdentifier'])) {
                echo "Remote server promotes malformed certificate\n";

                return 11;
            }
            if ($certificate_num == 0) {// @todo suppress
                // Проверяем домен сертификата (CN) и падаем, если нет suppress
                $c_names = [$b['subject']['CN']];
                if (isset($b['extensions'], $b['extensions']['subjectAltName'])) {
                    foreach (preg_split('_\\s*,\\s*_', $b['extensions']['subjectAltName']) as $dns) {
                        if (preg_match('_DNS:\\s*(\\S+)_', $dns, $dns_a)) {
                            $c_names[] = $dns_a[1];
                        }
                    }
                    unset($dns_a, $dns);
                    $c_names = array_unique($c_names);
                }
                $subject_found = false;
                foreach ($c_names as $c_name) {
                    $reg = str_replace(['.', '*'], ['\\.', '.+'], $c_name);
                    if (preg_match('_^'.$reg.'$_i', $domain)) {
                        $subject_found = true;
                        break;
                    }
                }
                if (!$subject_found) {
                    echo "CName mismatch\n";

                    return 13;
                }
                unset($c_name, $c_names, $subject_found, $reg, $certificate_num);
            }

            if ('keyid:'.trim($c['extensions']['subjectKeyIdentifier']) == trim($b['extensions']['authorityKeyIdentifier'])) {
                $found = true;
                break;
            }
        }
        if (!$found) {
            echo "Remote server promotes certificate with incorrect signer\n";

            return 12;
        }
        unset($a, $b, $c, $found);
    }

    if ($scenario == 0) {
        if (isset($settings->head)) {
            $head = $settings->head;
            $body = !empty($settings->body) ? $settings->body : '';
        } elseif (!isset($settings->answer)) {
            $body = !empty($settings->body) ? $settings->body : '';
            if (empty($body)) {
                $head = sprintf("GET / HTTP/1.0\r\nHost: %s", $domain);
            } else {
                $head = sprintf("POST / HTTP/1.0\r\nHost: %s\r\nContent-Length: %s", $domain, strlen($body));
            }
        } else {
            list($head, $body) = explode("\r\n\r\n", $settings->answer);
        }

        $at_once = isset($settings->at_once) ? $settings->at_once : true;

        $head_byte_per_interval = isset($settings->head_byte_per_interval) ? $settings->head_byte_per_interval : 4096;
        $head_interval = isset($settings->head_interval) ? (double) $settings->head_interval : null;
        if (isset($settings->head_byte_per_interval) or isset($settings->head_interval)) {
            $at_once = false;
        }

        $body_byte_per_interval = isset($settings->body_byte_per_interval) ? $settings->body_byte_per_interval : 4096;
        $body_interval = isset($settings->body_interval) ? (double) $settings->body_interval : null;
        if (isset($settings->body_byte_per_interval) or isset($settings->body_interval)) {
            $at_once = false;
        }

        if (isset($settings->interval_before_body) and ($settings->interval_before_body > 0)) {
            $at_once = false;
        }

        // Начинаем посылать
        if (isset($settings->interval_before_head)) {
            usleep($settings->interval_before_head * 1000000);
        }

        if ($at_once) {
            // Всё вместе
            fwrite($client_socket, "{$head}\r\n\r\n{$body}");
        } else {
            // По частям
            // Посылаем голову
            if (is_null($head_interval)) {
                fwrite($client_socket, "{$head}\r\n\r\n");
            } else {
                $head_left = "{$head}\r\n\r\n";

                while (!empty($head_left)) {
                    if (is_array($head_byte_per_interval)) {
                        $strlen = min(strlen($head_left), mt_rand($head_byte_per_interval[0], $head_byte_per_interval[1]));
                    } else {
                        $strlen = min(strlen($head_left), $head_byte_per_interval);
                    }

                    fwrite($client_socket, substr($head_left, 0, $strlen));
                    $head_left = substr($head_left, $strlen);
                    if (!empty($head_left)) {
                        usleep(1000000 * (is_array($head_interval)
                                ? mt_rand($head_interval[0], $head_interval[1]) : $head_interval));
                    }
                }
            }

            // интервал до body
            if (isset($settings->interval_before_body)) {
                usleep($settings->interval_before_body * 1000000);
            }

            // Посылаем body
            if (is_null($body_interval)) {
                fwrite($client_socket, $body);
            } else {
                $body_left = $body;

                while (!empty($body_left)) {
                    if (is_array($body_byte_per_interval)) {
                        $strlen = min(strlen($body_left), mt_rand($body_byte_per_interval[0], $body_byte_per_interval[1]));
                    } else {
                        $strlen = min(strlen($body_left), $body_byte_per_interval);
                    }

                    fwrite($client_socket, substr($body_left, 0, $strlen));
                    $body_left = substr($body_left, $strlen);
                    if (!empty($body_left)) {
                        usleep(1000000 * (is_array($body_interval)
                                ? mt_rand($body_interval[0], $body_interval[1]) : $body_interval));
                    }
                }
            }
        }

        stream_set_blocking($client_socket, 0);
        // Получаем ответ
        $answer = '';
        $wait_until = microtime(true) + 15;// @todo константу в конфиги
        do {
            $read = [$client_socket];
            $left = $wait_until - microtime(true);
            $write = null;
            $except = null;
            if ($left > 0) {
                $ret = stream_select($read, $write, $except,
                    (int) floor($left), (int) floor(($left - floor($left)) * 1000000));
            } else {
                $ret = stream_select($read, $write, $except, 0);
            }
            if ($ret === false) {
                echo "Socket selected returned false: ".socket_last_error()."\n";

                return 7;
            }
            if (empty($read) and empty($write)) {
                break;
            } elseif (empty($read)) {
                continue;
            }
            $buf = fread($client_socket, 4096);
            if (empty($buf)) {
                break;
            }
            $answer .= $buf;
            $wait_until += 15;// @todo константу в конфиги
        } while (true);

        if (!preg_match('_^HTTP/1\\.[01]\\s+([0-9]+)_', $answer, $a)) {
            echo "Malformed http answer\n";
        } elseif (($a[1] >= 200) and ($a[1] < 300)) {
            file_put_contents($settings->output_filename, $answer, LOCK_EX);
        } else {
            echo sprintf("\nBorg ERROR %d: \n", $a[1]);
        }
        fclose($client_socket);

        echo "done\n";

        return 0;
    } else {
        echo "No such scenario\n";

        return 6;
    }
    // @todo сценарии

?>