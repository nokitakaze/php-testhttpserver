<?php

    namespace NokitaKaze\TestHTTPServer;

    class ServerTest extends \PHPUnit_Framework_TestCase {
        protected static $_folder = null;

        /**
         * @var Server
         */
        static protected $_server;

        /**
         * @var boolean Запрос прошёл (onRequest fired)
         */
        static $request_success;

        /**
         * @var boolean Плохой коннект (onInvalidConnection fired)
         */
        static $request_invalid_connection;

        protected $_current_dir = null;

        function setUp() {
            parent::setUp();
            $this->_current_dir = getcwd();
            if (!is_null(self::$_server)) {
                self::$_server->shutdown();
                self::$_server = null;
            }
        }

        function tearDown() {
            chdir($this->_current_dir);
            if (!is_null(self::$_server)) {
                self::$_server->shutdown();
                self::$_server = null;
            }
            parent::tearDown();
        }

        /**
         * @throws \Exception
         *
         * @doc http://man.openbsd.org/x509v3.cnf.5
         * @doc https://opensource.apple.com/source/OpenSSL/OpenSSL-12/openssl/doc/openssl.txt.auto.html
         * @doc https://www.openssl.org/docs/manmaster/man5/x509v3_config.html
         */
        static function setUpBeforeClass() {
            parent::setUpBeforeClass();
            self::$_folder = sys_get_temp_dir().'/nkt_test_http_server_'.mt_rand(0, 100000);
            mkdir(self::$_folder);

            // Рутовый сертификат CA #A1
            // Сертификат CA #A2, подписанный CA #A1 (с возможностью подписи)
            // Сертификат CA #A3, подписанный CA #A2
            // Сертификат CA #A4, подписанный CA #A1 (без возможности подписи)

            // Рутовый сертификат CA #B1
            // Сертификат CA #B2, подписанный CA #B1 (с возможностью подписи)
            // Сертификат CA #B3, подписанный CA #B2
            // Сертификат CA #B4, подписанный CA #B1 (без возможности подписи)
            $temporary_openssl_file_conf = self::$_folder.'/openssl-config.tmp';
            file_put_contents($temporary_openssl_file_conf, 'HOME = .
RANDFILE = $ENV::HOME/.rnd
[ v3_intermediate ]
keyUsage               = critical,keyCertSign,cRLSign
basicConstraints       = critical,CA:true,pathlen:0
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
certificatePolicies    = @polsect

[polsect]
policyIdentifier       = 1.2.3.4.5.6.7
userNotice.1           = @notice

[notice]
explicitText           = "UTF8:Please add this certificate to black list. https://github.com/nokitakaze/php-testhttpserver"
organization           = "Nokita Kaze"
');
            $temporary_openssl_file_conf_alt = self::$_folder.'/openssl-config-alt.tmp';
            file_put_contents($temporary_openssl_file_conf_alt, sprintf('HOME = .
RANDFILE = $ENV::HOME/.rnd
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req

[ req_distinguished_name ]

[ v3_req ]
subjectAltName         = DNS:*.org, DNS:127.0.0.1, DNS:%s
keyUsage               = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign
basicConstraints       = CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
extendedKeyUsage       = serverAuth,clientAuth
certificatePolicies    = @polsect

[polsect]
policyIdentifier       = 1.2.3.4.5.6.7
userNotice.1           = @notice

[notice]
explicitText           = "UTF8:Please add this certificate to black list. https://github.com/nokitakaze/php-testhttpserver"
organization           = "Nokita Kaze"
', strtolower(gethostname())));
            $certificate_offset = mt_rand(0, 10000) << 16;
            foreach (['a', 'b'] as $prefix) {
                // CA #A1
                $csr_a1 = openssl_csr_new([
                    "countryName" => "RU",
                    "localityName" => "Kazan",
                    "organizationName" => "NKT",
                    "organizationalUnitName" => "Development Center. CA #{$prefix}1",
                    "commonName" => "NK: Test HTTP Server: CA #{$prefix}1",
                    "emailAddress" => "admin@kanaria.ru",
                ], $ca_a1_pair, [
                    'private_key_bits' => 2048,
                    'private_key_type' => OPENSSL_KEYTYPE_RSA, // currently only RSA works
                    'encrypt_key' => true,
                ]);
                if ($csr_a1 === false) {
                    throw new \Exception("Can not create CSR pair {$prefix}1");
                }
                $crt_a1 = openssl_csr_sign($csr_a1, null, $ca_a1_pair, 1, [
                    "digest_alg" => "sha256",
                ], hexdec("0{$prefix}1") + $certificate_offset);
                if ($crt_a1 === false) {
                    throw new \Exception("Can not create certificate {$prefix}1");
                }

                /** @noinspection PhpUndefinedVariableInspection */
                openssl_x509_export($crt_a1, $certout);
                openssl_pkey_export($ca_a1_pair, $pkeyout);
                file_put_contents(self::$_folder.'/crt_'.$prefix.'1.crt', $certout, LOCK_EX);
                file_put_contents(self::$_folder.'/crt_'.$prefix.'1.pem', $pkeyout, LOCK_EX);
                openssl_pkey_export($ca_a1_pair, $pkeyout, 'password');
                file_put_contents(self::$_folder.'/crt_'.$prefix.'1.p.pem', $pkeyout, LOCK_EX);
                unset($csr_a1, $certout, $pkeyout);

                // CA #A2
                $csr_a2 = openssl_csr_new([
                    "countryName" => "RU",
                    "localityName" => "Kazan",
                    "organizationName" => "NKT",
                    "organizationalUnitName" => "Development Center",
                    "commonName" => "NK: Test HTTP Server: CA #{$prefix}2",
                    "emailAddress" => "admin@kanaria.ru",
                ], $ca_a2_pair, [
                    'private_key_bits' => 2048,
                    'private_key_type' => OPENSSL_KEYTYPE_RSA, // currently only RSA works
                    'encrypt_key' => true,
                ]);
                if ($csr_a2 === false) {
                    throw new \Exception("Can not create CSR pair {$prefix}2");
                }
                $crt_a2 = openssl_csr_sign($csr_a2, file_get_contents(self::$_folder.'/crt_'.$prefix.'1.crt'),
                    $ca_a1_pair, 1, [
                        "digest_alg" => "sha256",
                        'config' => $temporary_openssl_file_conf,
                        'x509_extensions' => 'v3_intermediate',
                    ], hexdec("0{$prefix}2") + $certificate_offset);
                if ($crt_a2 === false) {
                    throw new \Exception("Can not create certificate {$prefix}2");
                }

                /** @noinspection PhpUndefinedVariableInspection */
                openssl_x509_export($crt_a2, $certout);
                openssl_pkey_export($ca_a2_pair, $pkeyout);
                file_put_contents(self::$_folder.'/crt_'.$prefix.'2.crt', $certout, LOCK_EX);
                file_put_contents(self::$_folder.'/crt_'.$prefix.'2.c.crt',
                    $certout."\n".file_get_contents(self::$_folder.'/crt_'.$prefix.'1.crt'), LOCK_EX);
                file_put_contents(self::$_folder.'/crt_'.$prefix.'2.pem', $pkeyout, LOCK_EX);
                openssl_pkey_export($ca_a2_pair, $pkeyout, 'password');
                file_put_contents(self::$_folder.'/crt_'.$prefix.'2.p.pem', $pkeyout, LOCK_EX);
                unset($csr_a2, $certout, $pkeyout);

                // CA #A3
                $csr_a3 = openssl_csr_new([
                    "countryName" => "RU",
                    "localityName" => "Kazan",
                    "organizationName" => "NKT",
                    "organizationalUnitName" => "Development Center",
                    "commonName" => "NK: Test HTTP Server: CA #{$prefix}3",
                    "emailAddress" => "admin@kanaria.ru",
                ], $ca_a3_pair, [
                    'private_key_bits' => 2048,
                    'private_key_type' => OPENSSL_KEYTYPE_RSA, // currently only RSA works
                    'encrypt_key' => true,
                ]);
                if ($csr_a3 === false) {
                    throw new \Exception("Can not create CSR pair {$prefix}3");
                }
                $crt_a3 = openssl_csr_sign($csr_a3, file_get_contents(self::$_folder.'/crt_'.$prefix.'2.crt'),
                    $ca_a2_pair, 1, [
                        "digest_alg" => "sha256",
                        'config' => $temporary_openssl_file_conf_alt,
                        'x509_extensions' => 'v3_req',
                    ], hexdec("0{$prefix}3") + $certificate_offset);
                if ($crt_a3 === false) {
                    throw new \Exception("Can not create certificate {$prefix}3");
                }

                /** @noinspection PhpUndefinedVariableInspection */
                openssl_x509_export($crt_a3, $certout);
                openssl_pkey_export($ca_a3_pair, $pkeyout);
                file_put_contents(self::$_folder.'/crt_'.$prefix.'3.crt', $certout, LOCK_EX);
                file_put_contents(self::$_folder.'/crt_'.$prefix.'3.c.crt',
                    $certout."\n".file_get_contents(self::$_folder.'/crt_'.$prefix.'2.c.crt'), LOCK_EX);
                file_put_contents(self::$_folder.'/crt_'.$prefix.'3.pem', $pkeyout, LOCK_EX);
                openssl_pkey_export($ca_a3_pair, $pkeyout, 'password');
                file_put_contents(self::$_folder.'/crt_'.$prefix.'3.p.pem', $pkeyout, LOCK_EX);
                unset($csr_a3, $certout, $pkeyout);

                // CA #A4
                $csr_a4 = openssl_csr_new([
                    "countryName" => "RU",
                    "localityName" => "Kazan",
                    "organizationName" => "NKT",
                    "organizationalUnitName" => "Development Center",
                    "commonName" => "NK: Test HTTP Server: CA #{$prefix}4",
                    "emailAddress" => "admin@kanaria.ru",
                ], $ca_a4_pair, [
                    'private_key_bits' => 2048,
                    'private_key_type' => OPENSSL_KEYTYPE_RSA, // currently only RSA works
                    'encrypt_key' => true,
                ]);
                if ($csr_a4 === false) {
                    throw new \Exception("Can not create CSR pair {$prefix}4");
                }
                $crt_a4 = openssl_csr_sign($csr_a4, file_get_contents(self::$_folder.'/crt_'.$prefix.'1.crt'),
                    $ca_a1_pair, 1, [
                        "digest_alg" => "sha256",
                        'config' => $temporary_openssl_file_conf_alt,
                        'x509_extensions' => 'v3_req',
                    ], hexdec("0{$prefix}4") + $certificate_offset);
                if ($crt_a4 === false) {
                    throw new \Exception("Can not create certificate {$prefix}4");
                }

                /** @noinspection PhpUndefinedVariableInspection */
                openssl_x509_export($crt_a4, $certout);
                openssl_pkey_export($ca_a4_pair, $pkeyout);
                file_put_contents(self::$_folder.'/crt_'.$prefix.'4.crt', $certout, LOCK_EX);
                file_put_contents(self::$_folder.'/crt_'.$prefix.'4.c.crt',
                    $certout."\n".file_get_contents(self::$_folder.'/crt_'.$prefix.'1.crt'), LOCK_EX);
                file_put_contents(self::$_folder.'/crt_'.$prefix.'4.pem', $pkeyout, LOCK_EX);
                openssl_pkey_export($ca_a4_pair, $pkeyout, 'password');
                file_put_contents(self::$_folder.'/crt_'.$prefix.'4.p.pem', $pkeyout, LOCK_EX);
                unset($csr_a4, $certout, $pkeyout);
            }
            unlink($temporary_openssl_file_conf);
            unlink($temporary_openssl_file_conf_alt);
        }

        static function tearDownAfterClass() {
            exec(sprintf('rm -rf %s', escapeshellarg(self::$_folder)), $buf);

            $buf = "testListeningScenario profiling:\n";
            foreach (self::$_testListeningScenario_bind as $index => $ts) {
                $buf .= sprintf("{$index}\t{$ts}\n");
            }
            file_put_contents(__DIR__.'/testListeningScenario_profiling.txt', $buf, LOCK_EX);

            parent::tearDownAfterClass();
        }

        protected static $_used_ports = [];

        /**
         * @return int
         */
        static function get_port() {
            exec('netstat -n -t', $buf);
            $current_used_ports = [];
            foreach ($buf as $line) {
                list(, , , $local_addr,) = preg_split('_\\s+_', $line, 7);
                if (preg_match('_:([0-9]+)$_', $local_addr, $a)) {
                    $current_used_ports[] = (int) $a[1];
                }
            }
            $current_used_ports = array_unique($current_used_ports);
            sort($current_used_ports);

            do {
                $port = mt_rand(55000, 60000);
            } while (in_array($port, self::$_used_ports) or in_array($port, $current_used_ports));
            self::$_used_ports[] = $port;

            return $port;
        }

        function testListeningWithoutParams() {
            $port = 58080;
            self::$_server = new Server([]);

            self::$_server->init_listening();
            $filename = tempnam(self::$_folder, 'wget_output_');
            exec(sprintf('wget "http://127.0.0.1:%d/" -qO - --timeout=600 > %s 2>&1 &', $port, escapeshellarg($filename)));
            self::$_server->listen_tick();
        }

        function testListeningTimeout() {
            $port = self::get_port();

            self::$_server = new Server((object) [
                'port' => $port,
            ]);

            self::$_server->init_listening();
            $ts1 = microtime(true);
            self::$_server->listen_tick();
            $ts2 = microtime(true);
            $this->assertLessThan(5, $ts2 - $ts1);
        }

        /**
         * @param array[] $borg_ssl
         * @param array[] $borg_scenario
         *
         * @return array[]
         */
        protected function dataListening_multiple($borg_ssl, $borg_scenario) {
            $data = [];
            foreach ($borg_ssl as &$borg_ssl_single) {
                foreach ($borg_scenario as $datum) {
                    if (!isset($datum[2])) {
                        $datum[2] = [];
                        $datum[3] = [];
                    } elseif (!isset($datum[3])) {
                        $datum[3] = [];
                    }

                    if (!isset($datum[3])) {
                        $datum[3] = [];
                    }

                    foreach ($borg_ssl_single[0] as $key => $value) {
                        $datum[0][$key] = $value;
                    }
                    $datum[1] = ($datum[1] and $borg_ssl_single[1]);
                    foreach ($borg_ssl_single[2] as $key => $value) {
                        $datum[2][$key] = $value;
                    }
                    foreach ($borg_ssl_single[3] as $key => $value) {
                        $datum[3][$key] = $value;
                    }

                    // Меняем рандом
                    if (isset($datum[2]['expected_body']) and (strpos($datum[2]['expected_body'], '{random}') !== false)) {
                        $random_string = openssl_random_pseudo_bytes(30);
                        $datum[2]['expected_body'] = str_replace('{random}', $random_string, $datum[2]['expected_body']);

                        if ((isset($datum[3]['body']) and (strpos($datum[3]['body'], '{random}') !== false))) {
                            $datum[3]['body'] = str_replace('{random}', $random_string, $datum[3]['body']);
                        }
                        if ((isset($datum[3]['answer']) and (strpos($datum[3]['answer'], '{random}') !== false))) {
                            $datum[3]['answer'] = str_replace('{random}', $random_string, $datum[3]['answer']);
                        }
                    }

                    $datum[2]['borg'] = $datum[3];
                    $datum[3] = [];

                    $data[] = $datum;
                }
            }

            return $data;
        }

        protected function dataListeningScenario_multiple_wget($data2, $chunk_data) {
            $data = [];
            foreach ($data2 as $datum) {
                if (!isset($datum[2])) {
                    $datum[2] = [];
                    $datum[3] = [];
                } elseif (!isset($datum[3])) {
                    $datum[3] = [];
                }

                foreach ($chunk_data as &$inner) {
                    $datum2 = $datum;
                    list($u, $ca_filename, $ca_filename_key, $ca_filename_password,
                        $server_options, $wget_options,
                        $client_filename, $client_key) = $inner;

                    if (!$datum2[1]) {
                        // This is SSL Error, so no HTTP code
                        unset($datum2[2]['expected_error_code']);
                    }
                    $datum2[1] = ($datum2[1] and $u);
                    $datum2[2]['is_ssl'] = true;
                    $datum2[0]['is_ssl'] = true;
                    $datum2[0]['ssl_server_certificate_file'] = '{folder}/'.$ca_filename;
                    $datum2[0]['ssl_server_key_file'] = '{folder}/'.$ca_filename_key;
                    if (!is_null($ca_filename_password)) {
                        $datum2[0]['ssl_server_key_password'] = $ca_filename_password;
                    }
                    foreach ($server_options as $key => &$value) {
                        $datum2[0][$key] = $value;
                    }
                    $wget_options['--https-only'] = null;
                    if (!is_null($client_filename)) {
                        $wget_options['--certificate'] = $client_filename;
                    }
                    if (!is_null($client_key)) {
                        $wget_options['--private-key'] = $client_key;
                    }
                    foreach ($wget_options as $key => &$value) {
                        $datum2[3][$key] = $value;
                    }
                    unset($wget_options, $key, $value);

                    $data[] = $datum2;
                }
                unset($u, $ca_filename, $ca_filename_key, $server_options, $wget_options,
                    $client_filename, $client_key, $client_password, $inner, $datum2);
            }

            return $data;
        }

        /**
         * @return array[]
         */
        function dataListeningScenario() {
            $data = [];

            $hostname = strtolower(gethostname());

            // HTTP Only
            $data[] = [
                ['interface' => '127.0.0.1',],
                true,
                ['host' => '127.0.0.1'],
            ];
            $data[] = [
                ['interface' => '127.0.0.1',],
                false,
                ['host' => '127.0.0.2',],// connection refused
            ];
            $data[] = [
                ['interface' => '0.0.0.0',],
                true,
                ['host' => '127.0.0.1'],
            ];

            $data[] = [
                ['interface' => '0.0.0.0', 'is_ssl' => true, 'ssl_server_certificate_file' => '{folder}/crt_a1.crt',
                 'ssl_server_key_file' => '{folder}/crt_a1.pem',],
                true,
                ['host' => '127.0.0.2', 'is_ssl' => true,],
                ['--ca-certificate' => '{folder}/crt_a1.crt', '--no-check-certificate' => null,
                 '--https-only' => null,],
            ];
            $data[] = [
                ['interface' => '0.0.0.0', 'is_ssl' => true, 'ssl_server_certificate_file' => '{folder}/crt_a1.crt',
                 'ssl_server_key_file' => '{folder}/crt_a1.pem',],
                true,
                ['host' => '127.0.0.2', 'is_ssl' => true,],
                ['--ca-certificate' => '{folder}/crt_b1.crt', '--no-check-certificate' => null,
                 '--https-only' => null,],
            ];

            // HTTP & HTTPS
            $data2 = [];
            $data2[] = [
                ['accepted_hosts' => ['127.0.0.1', $hostname], 'interface' => '0.0.0.0',],
                true,
            ];
            $data2[] = [
                ['accepted_hosts' => ['127.0.0.1', $hostname], 'interface' => '0.0.0.0',],
                true,
                ['request_type' => 'POST',],
                ['--post-data' => 'key=value&foo=%27bar'],
            ];
            $data2[] = [
                ['accepted_hosts' => ['127.0.0.1'], 'interface' => '0.0.0.0',],
                false,
            ];
            $data2[] = [
                ['interface' => '0.0.0.0',],
                true,
            ];
            $data2[] = [
                ['accepted_hosts' => [mt_rand(0, 100000).'.example.com'], 'interface' => '0.0.0.0',],
                false,
                ['expected_error_code' => 404,],
            ];
            $data2[] = [
                ['accepted_hosts' => [mt_rand(0, 100000).'.example.com'], 'interface' => '0.0.0.0',
                 'onHostNotFound' => function ($server, $connect) {
                     /** @var ClientDatum $connect */
                     $connect->server->answer($connect, 404, 'Not found', 'There is no any onion');

                     return null;
                 },],
                false,
                ['expected_error_code' => 404,],
            ];
            $data2[] = [
                ['accepted_hosts' => [mt_rand(0, 100000).'.example.com'], 'interface' => '0.0.0.0',
                 'onHostNotFound' => function ($server, $connect) {
                     /** @var ClientDatum $connect */
                     $connect->server->answer($connect, 200, 'Not found', 'There is no any onion');
                     self::$request_success = true;

                     return false;
                 },],
                true,
                ['expected_body' => 'There is no any onion',],
            ];

            $chunk_data = [
                //
                [true, 'crt_a1.crt', 'crt_a1.pem', null, [],
                 ['--ca-certificate' => '{folder}/crt_a1.crt', '--no-check-certificate' => null,],
                 null, null],
                [true, 'crt_a2.c.crt', 'crt_a2.pem', null, [],
                 ['--ca-certificate' => '{folder}/crt_a1.crt', '--no-check-certificate' => null,],
                 null, null],
                [true, 'crt_a3.c.crt', 'crt_a3.pem', null, [],
                 ['--ca-certificate' => '{folder}/crt_a1.crt',],
                 null, null],
                [true, 'crt_a4.c.crt', 'crt_a4.pem', null, [],
                 ['--ca-certificate' => '{folder}/crt_a1.crt',],
                 null, null],

                //
                [false, 'crt_a1.crt', 'crt_a1.pem', null, [],// CN mismatch
                 ['--ca-certificate' => '{folder}/crt_a1.crt',],
                 null, null],
                [false, 'crt_a2.c.crt', 'crt_a2.pem', null, [],// CN mismatch
                 ['--ca-certificate' => '{folder}/crt_a1.crt',],
                 null, null],

                //
                [true, 'crt_a1.crt', 'crt_a1.pem', null, [],
                 ['--ca-certificate' => '{folder}/crt_b1.crt', '--no-check-certificate' => null,],
                 null, null],
                [true, 'crt_a2.c.crt', 'crt_a2.pem', null, [],
                 ['--ca-certificate' => '{folder}/crt_b1.crt', '--no-check-certificate' => null,],
                 null, null],
                [false, 'crt_a1.crt', 'crt_a1.pem', null, [],//CN mismatch
                 ['--ca-certificate' => '{folder}/crt_b1.crt',],
                 null, null],
                [false, 'crt_a2.c.crt', 'crt_a2.pem', null, [],// CN mismatch
                 ['--ca-certificate' => '{folder}/crt_b1.crt',],
                 null, null],
                [false, 'crt_a3.c.crt', 'crt_a3.pem', null, [],// Incorrect CA
                 ['--ca-certificate' => '{folder}/crt_b1.crt',],
                 null, null],
                [false, 'crt_a4.c.crt', 'crt_a4.pem', null, [],// Incorrect CA
                 ['--ca-certificate' => '{folder}/crt_b1.crt',],
                 null, null],
            ];

            $data = array_merge($data, $data2,
                $this->dataListeningScenario_multiple_wget($data2, [$chunk_data[0], $chunk_data[1], $chunk_data[4]]),
                $this->dataListeningScenario_multiple_wget([$data2[0], $data2[2], $data2[3],], $chunk_data)
            );
            unset($data2, $datum, $datum2, $chunk_data);

            /**
             * Borg
             */
            // 1. Без SSL
            // 2. С SSL без ключей клиентов
            // 3. С SSL с ключом клиента, но клиент без ключа (ssl_client_certificate_file)
            // 4. С SSL с ключом клиента, но клиент с неправильным ключом
            // 5. С SSL с ключом клиента, но клиент с правильным ключом (от этого CA)
            // 6. С SSL с ключом клиента, но клиент с правильным ключом (от Intermediate CA)

            // get, body без тела, body с телом
            $borg_ssl = [
                [
                    // 1. Без SSL
                    [],
                    true,
                    [],
                    [],// borg settings
                ], [
                    // 2. С SSL без ключей клиентов
                    ['ssl_server_certificate_file' => '{folder}/crt_a3.c.crt',
                     'ssl_server_key_file' => '{folder}/crt_a3.pem',
                     'is_ssl' => true,],
                    true,
                    [],
                    ['ssl_server_certificate_file' => '{folder}/crt_a1.crt',
                     'is_ssl' => true,],// borg settings
                ], [
                    // 2.a. С SSL без ключей клиентов (другой сертификат)
                    ['ssl_server_certificate_file' => '{folder}/crt_a3.c.crt',
                     'ssl_server_key_file' => '{folder}/crt_a3.pem',
                     'is_ssl' => true,],
                    true,
                    [],
                    ['ssl_server_certificate_file' => '{folder}/crt_a2.crt',
                     'is_ssl' => true,],// borg settings
                ], [
                    // 2.c. С SSL без ключей клиентов (только конечный серт, без чейна)
                    ['ssl_server_certificate_file' => '{folder}/crt_a3.crt',
                     'ssl_server_key_file' => '{folder}/crt_a3.pem',
                     'is_ssl' => true,],
                    false,
                    [],
                    ['ssl_server_certificate_file' => '{folder}/crt_a1.crt',
                     'is_ssl' => true,],// borg settings
                ], [
                    // 2.d. С SSL без ключей клиентов (только конечный серт, без CA)
                    ['ssl_server_certificate_file' => '{folder}/crt_a4.c.crt',
                     'ssl_server_key_file' => '{folder}/crt_a4.pem',
                     'is_ssl' => true,],
                    true,
                    [],
                    ['ssl_server_certificate_file' => '{folder}/crt_a1.crt',
                     'is_ssl' => true,],// borg settings
                ], [
                    // 3. С SSL с ключом клиента, но клиент без ключа (ssl_client_certificate_file)
                    ['ssl_server_certificate_file' => '{folder}/crt_a3.c.crt',
                     'ssl_server_key_file' => '{folder}/crt_a3.pem',
                     'ssl_client_certificate_file' => '{folder}/crt_a1.crt',
                     'is_ssl' => true,],
                    false,
                    ['expected_invalid_connection' => true,],
                    ['ssl_server_certificate_file' => '{folder}/crt_a1.crt',
                     'is_ssl' => true,],// borg settings
                ], [
                    // 4. С SSL с ключом клиента, но клиент с неправильным ключом
                    ['ssl_server_certificate_file' => '{folder}/crt_a3.c.crt',
                     'ssl_server_key_file' => '{folder}/crt_a3.pem',
                     'ssl_client_certificate_file' => '{folder}/crt_a1.crt',
                     'is_ssl' => true,],
                    false,
                    ['expected_invalid_connection' => true,],
                    ['ssl_server_certificate_file' => '{folder}/crt_a1.crt',
                     'ssl_client_certificate_file' => '{folder}/crt_b3.c.crt',
                     'ssl_client_key_file' => '{folder}/crt_a3.pem',
                     'is_ssl' => true,],// borg settings
                ], [
                    // 5. С SSL с ключом клиента, но клиент с правильным ключом (от этого CA)
                    ['ssl_server_certificate_file' => '{folder}/crt_a3.c.crt',
                     'ssl_server_key_file' => '{folder}/crt_a3.pem',
                     'ssl_client_certificate_file' => '{folder}/crt_a1.crt',
                     'is_ssl' => true,],
                    true,
                    [],
                    ['ssl_server_certificate_file' => '{folder}/crt_a1.crt',
                     'ssl_client_certificate_file' => '{folder}/crt_a3.c.crt',
                     'ssl_client_key_file' => '{folder}/crt_a3.pem',
                     'is_ssl' => true,],// borg settings
                ], [
                    // 6. С SSL с ключом клиента, но клиент с правильным ключом (от Intermediate CA)
                    ['ssl_server_certificate_file' => '{folder}/crt_a3.c.crt',
                     'ssl_server_key_file' => '{folder}/crt_a3.pem',
                     'ssl_client_certificate_file' => '{folder}/crt_a1.crt',
                     'is_ssl' => true,],
                    true,
                    [],
                    ['ssl_server_certificate_file' => '{folder}/crt_a1.crt',
                     'ssl_client_certificate_file' => '{folder}/crt_a4.c.crt',
                     'ssl_client_key_file' => '{folder}/crt_a4.pem',
                     'is_ssl' => true,],// borg settings
                ],
            ];

            // Сценарии
            // 1. GET  [100 байт в секунду]
            // 2. POST [HEAD: 100 байт в секунду; BODY: 100 килобайт, килобайт в секунду]
            // 3. POST [HEAD: 100 байт в секунду; BODY: 1 мегабайт, 10 килобайт в секунду]
            // 4. Интервал перед головой 60 сек => fault
            // 5. Интервал перед телом 60 сек => fault
            // 6. peer_name!=host, когда IP открывается напрямую, а...

            $borg_scenario = [
                [
                    [],
                    true,
                    ['expected_body' => '{random}', 'wait_for_request' => 5,],
                    [],// borg settings
                ], [
                    // 1. GET  [100 байт в секунду]
                    [],
                    true,
                    ['expected_body' => '{random}', 'head_byte_per_interval' => 100, 'head_interval' => 1,
                     'wait_for_request' => 15,],
                    [],// borg settings
                ], [
                    // 2. POST [HEAD: 100 байт в секунду; BODY: 100 килобайт, килобайт в секунду]
                    [],
                    true,
                    ['request_type' => 'POST', 'wait_for_request' => 20,],
                    ['head_byte_per_interval' => 100, 'head_interval' => 1,
                     'body_byte_per_interval' => 1024, 'body_interval' => 1,
                     'body' => openssl_random_pseudo_bytes(10 * 1024),],// borg settings
                ], [
                    // 6. peer_name!=host, когда IP открывается напрямую, а...
                    ['interface' => '127.0.0.1', 'accepted_hosts' => ['example.org']],
                    true,
                    ['host' => 'example.org'],
                    ['host' => '127.0.0.1', 'domain' => 'example.org'],// borg settings
                ],
            ];
            $data = array_merge($data,
                $this->dataListening_multiple($borg_ssl, [$borg_scenario[0], $borg_scenario[2],]),
                $this->dataListening_multiple([$borg_ssl[0], $borg_ssl[1], $borg_ssl[8]], $borg_scenario)
            );

            /**
             * Более тонкие сценарии
             */
            // @hint Эти сценарии не обязательно проверять на всех SSL-сценариях
            $borg_scenario = [
                [
                    [],
                    true,
                    ['expected_body' => '{random}', 'wait_for_request' => 180,],
                    [],// borg settings
                ], [
                    // 1. GET  [100 байт в секунду]
                    [],
                    true,
                    ['expected_body' => '{random}', 'head_byte_per_interval' => 100, 'head_interval' => 1,
                     'wait_for_request' => 180,],
                    [],// borg settings
                ], [
                    // 4. Интервал перед головой 30 сек => fault
                    ['time_wait_until_first_byte' => 10,],
                    false,
                    ['expected_body' => '{random}', 'wait_for_request' => 180,],
                    ['interval_before_head' => 30,],// borg settings
                ], [
                    // 5. Интервал перед телом 30 сек => fault
                    ['time_between_head_and_body_received' => 10,],
                    false,
                    ['request_type' => 'POST', 'expected_body' => '{random}',],
                    ['interval_before_body' => 30, 'body' => openssl_random_pseudo_bytes(1024)],// borg settings
                ], [
                    // Интервалы слишком большие, тело не успевает приходить и запрос падает
                    ['time_wait_until_request_received' => 10,],
                    false,
                    ['expected_body' => '{random}', 'wait_for_request' => 180,],
                    ['interval_before_head' => 10, 'interval_before_body' => 10,],// borg settings
                ], [
                    // [10 байт в секунду, 5 байт до ожидания головы и падение]
                    ['time_wait_until_head_received' => 5,],
                    false,
                    ['expected_body' => '{random}', 'wait_for_request' => 180,],
                    ['head_byte_per_interval' => [5, 10], 'head_interval' => 3,],// borg settings
                ], [
                    // 2. POST [HEAD: 100 байт в секунду; BODY: 100 килобайт, килобайт в секунду]
                    [],
                    true,
                    ['request_type' => 'POST', 'wait_for_request' => 600,],
                    ['head_byte_per_interval' => 100, 'head_interval' => 1,
                     'body_byte_per_interval' => 1024, 'body_interval' => 1,
                     'body' => openssl_random_pseudo_bytes(100 * 1024)],// borg settings
                ], [
                    // Получаем не больше чем 4 килобайтай за один раз
                    ['server_maximum_chunk' => 4096],
                    true,
                    ['request_type' => 'POST', 'wait_for_request' => 600,],
                    ['body_byte_per_interval' => [1024, 10240], 'body_interval' => 1,
                     'body' => openssl_random_pseudo_bytes(100 * 1024)],// borg settings
                ], [
                    // 3. POST [HEAD: 100 байт в секунду; BODY: 1 мегабайт, 10 килобайт в секунду]
                    [],
                    true,
                    ['request_type' => 'POST', 'wait_for_request' => 180,],
                    ['head_byte_per_interval' => 100, 'head_interval' => 1,
                     'body_byte_per_interval' => 10240, 'body_interval' => 1,
                     'body' => openssl_random_pseudo_bytes(1024 * 1024)],// borg settings
                ], [
                    // 6. peer_name!=host, когда IP открывается напрямую, а...
                    ['interface' => '127.0.0.1', 'accepted_hosts' => ['example.org']],
                    true,
                    ['host' => 'example.org'],
                    ['host' => '127.0.0.1', 'domain' => 'example.org'],// borg settings
                ], [
                    // Неправильный HTTP-запрос
                    [],
                    false,
                    ['expected_error_code' => 400],
                    ['head' => "G0T / HTTP/1.0\r\nHost: grapearl"],// borg settings
                ], [
                    // Неправильный HTTP-запрос (с гашением)
                    ['onHeadInvalidReceived' => function ($server, $connect) {
                        /* @var Server $server */
                        $server->answer($connect, 459, 'Fahrenheit', 'Malformed request');

                        return false;
                    },],
                    false,
                    ['expected_error_code' => 459],
                    ['head' => "G0T / HTTP/1.0\r\nHost: grapearl"],// borg settings
                ], [
                    // Неподдерживаемый HTTP-запрос
                    [],
                    false,
                    ['expected_error_code' => 400],
                    ['head' => "HEAD / HTTP/1.0\r\nHost: grapearl"],// borg settings
                ], [
                    // Неподдерживаемый HTTP-запрос (с гашением)
                    ['onHeadInvalidReceived' => function ($server, $connect) {
                        /* @var Server $server */
                        $server->answer($connect, 459, 'Fahrenheit', 'Malformed request');

                        return false;
                    },],
                    false,
                    ['expected_error_code' => 459],
                    ['head' => "HEAD / HTTP/1.0\r\nHost: grapearl"],// borg settings
                ], [
                    // Плохое поле в HEAD
                    [],
                    false,
                    ['expected_error_code' => 400],
                    ['head' => "GET / HTTP/1.0\r\nHost: grapearl\r\nX-侍の道:"],// borg settings
                ], [
                    // Плохое поле в HEAD (с гашением)
                    ['onHeadInvalidReceived' => function ($server, $connect) {
                        /* @var Server $server */
                        $server->answer($connect, 459, 'Fahrenheit', 'Malformed request');

                        return false;
                    },],
                    false,
                    ['expected_error_code' => 459],
                    ['head' => "GET / HTTP/1.0\r\nHost: grapearl\r\nX-侍の道:"],// borg settings
                ], [
                    // Пропало поле Host
                    [],
                    false,
                    ['expected_error_code' => 400,],
                    ['head' => "GET / HTTP/1.0\r\nX-header: I just placeholder"],// borg settings
                ], [
                    // Тестируем filterIncomingConnect
                    ['filterIncomingConnect' => function ($server, $connect) {
                        /* @var Server $server */
                        $server->answer($connect, 459, 'Fahrenheit', 'filterIncomingConnect');

                        return false;
                    },],
                    false,
                    ['expected_error_code' => 459,],
                    ['head' => "GET / HTTP/1.0\r\nHost: grapearl"],// borg settings
                ], [
                    // POST-запрос без Content-Length
                    [],
                    false,
                    ['request_type' => 'POST', 'expected_error_code' => 400,],
                    ['head' => "POST / HTTP/1.0\r\nHost: grapearl",
                     'body' => openssl_random_pseudo_bytes(10 * 1024)],// borg settings
                ], [
                    // POST-запрос без Content-Length (с гашением)
                    ['onHeadInvalidReceived' => function ($server, $connect) {
                        /* @var Server $server */
                        $server->answer($connect, 459, 'Fahrenheit', 'filterIncomingConnect');

                        return false;
                    },],
                    false,
                    ['request_type' => 'POST', 'expected_error_code' => 459,],
                    ['head' => "POST / HTTP/1.0\r\nHost: grapearl",
                     'body' => openssl_random_pseudo_bytes(10 * 1024)],// borg settings
                ],
            ];

            $borg_ssl = [$borg_ssl[0], $borg_ssl[1]];
            $data = array_merge($data, $this->dataListening_multiple($borg_ssl, $borg_scenario));
            // @todo X-Заголовок в HEAD тоже проверить

            // Обрабатываем
            foreach ($data as &$datum) {
                if (!isset($datum[2])) {
                    $datum[2] = [];
                    $datum[3] = [];
                } elseif (!isset($datum[3])) {
                    $datum[3] = [];
                }
            }

            return $data;
        }

        /**
         * @return array[]
         */
        function dataListeningScenario2() {
            $data2 = [];

            $data2[] = [
                // Неправильный HTTP-запрос
                [],
                false,
                ['expected_error_code' => 400, 'borg' => ['head' => "G0T / HTTP/1.0\r\nHost: grapearl"]],
                [],// borg settings
            ];
            $data2[] = [
                // POST-запрос без Content-Length
                ['HeadInvalidReceived' => function ($server, $connect) {
                    /* @var Server $server */
                    $server->answer($connect, 459, 'Fahrenheit', 'filterIncomingConnect');

                    return false;
                },],
                false,
                [
                    'request_type' => 'POST', 'expected_error_code' => 459,
                    'borg' => [
                        'head' => "POST / HTTP/1.0\r\nHost: grapearl",
                        'body' => openssl_random_pseudo_bytes(10 * 1024),
                    ],
                ],
                [],// borg settings
            ];

            foreach ($data2 as &$datum) {
                if (!isset($datum[2])) {
                    $datum[2] = [];
                    $datum[3] = [];
                } elseif (!isset($datum[3])) {
                    $datum[3] = [];
                }
            }

            return [$data2[1]];
        }

        protected static $_testListeningScenario_bind = [0, 0, 0, 0, 0, 0, 0, 0, 0,];

        /**
         * @param array   $server_settings
         * @param boolean $expected_request_success
         * @param array   $options Опции к самому тесту
         * @param array   $wget_options
         *
         * @dataProvider dataListeningScenario
         */
        function testListeningScenario(array $server_settings, $expected_request_success, array $options, array $wget_options) {
            $ts_1 = microtime(true);
            $port = self::get_port();

            if (!isset($options['is_ssl'])) {
                $options['is_ssl'] = false;
            }
            if (!isset($options['host'])) {
                $options['host'] = strtolower(gethostname());
            }

            self::$request_success = false;
            self::$request_invalid_connection = false;
            $obj = $this;
            $full_server_settings = [
                'port' => $port,
                'onRequest' => function ($server, $connect) use ($obj, $port, $options) {
                    /** @var ClientDatum $connect */
                    $connect->server->answer($connect, 200, 'OK',
                        isset($options['expected_body']) ? $options['expected_body'] : 'la tortuga: '.$port);

                    self::$request_success = true;
                    $obj->assertEquals('/', $connect->request_url, 'Request url mismatch');
                    $obj->assertEquals(isset($options['request_type'])
                        ? $options['request_type'] : 'GET', $connect->request_type,
                        'Request type mismatch');
                    $obj->assertTrue(
                        ($options['host'].':'.$port == $connect->request_head_params['Host']) or
                        ($options['host'] == $connect->request_head_params['Host']),
                        'Request host mismatch'
                    );

                    $connect->status = 3;
                },
                'onInvalidConnection' => function () use ($obj) {
                    $obj::$request_invalid_connection = true;
                },
            ];
            foreach ($server_settings as $key => &$value) {
                $full_server_settings[$key] = $value;
            }
            foreach ($full_server_settings as $key => &$value) {
                if (is_string($value)) {
                    $value = str_replace('{folder}', self::$_folder, $value);
                }
            }
            unset($server_settings, $key, $value);
            $ts_2 = microtime(true);
            self::$_server = new Server((object) $full_server_settings);

            self::$_server->init_listening();
            $ts_3 = microtime(true);
            $filename = tempnam(self::$_folder, 'wget_output_');
            $filename_console = tempnam(self::$_folder, 'wget_console_');
            $wait_for_request = isset($options['wait_for_request']) ? (double) $options['wait_for_request'] : 5;
            $wait_between_req_and_file = isset($options['wait_between_req_and_file'])
                ? (double) $options['wait_between_req_and_file'] : 5;

            if (isset($options['borg'])) {
                $options_borg = $options['borg'];
                $options_borg['output_filename'] = $filename;
                $options_borg['port'] = $port;
                foreach ($options_borg as $key => &$value) {
                    if (is_string($value) and (strpos($value, '{folder}/') !== false)) {
                        $value = str_replace('{folder}/', self::$_folder.'/', $value);
                    }
                }
                $borg_config_file = tempnam(self::$_folder, 'borg_config_');
                file_put_contents($borg_config_file, serialize($options_borg), LOCK_EX);

                $borg_script = sprintf(sprintf('sleep %d && php '.__DIR__.'/bin/borg.php --config=%s > %s 2>&1 &',
                    isset($options['sleep_before_wget']) ? (int) $options['sleep_before_wget'] : 0,
                    escapeshellarg($borg_config_file),
                    escapeshellarg($filename_console)
                ));
                exec($borg_script);
            } else {
                $wget_options_string = '';
                if (!isset($wget_options['--timeout'])) {
                    $wget_options['--timeout'] = 30;
                }
                foreach ($wget_options as $key => $value) {
                    if (is_null($value)) {
                        $wget_options_string .= ' '.$key;
                    } else {
                        $wget_options_string .= " {$key}=".escapeshellarg(str_replace('{folder}', self::$_folder, $value));
                    }
                }

                $wget_script = sprintf('sleep %d && wget "%s://%s:%d%s" %s -O %s --save-headers > %s 2>&1 &',
                    isset($options['sleep_before_wget']) ? (int) $options['sleep_before_wget'] : 0,
                    $options['is_ssl'] ? 'https' : 'http',
                    $options['host'],
                    $port,
                    isset($options['url']) ? $options['url'] : '/',//url
                    $wget_options_string,
                    escapeshellarg($filename),
                    escapeshellarg($filename_console));
                exec($wget_script);
            }

            $ts_4 = microtime(true);
            do {
                self::$_server->listen_tick();
            } while ((microtime(true) <= $ts_4 + $wait_for_request) and
                     !self::$request_success and !self::$request_invalid_connection);
            $ts_5 = microtime(true);
            if (self::$request_success) {
                $ts2 = microtime(true);
                // @hint filesize не робит
                while ((microtime(true) <= $ts2 + $wait_between_req_and_file) and empty(file_get_contents($filename))) {
                    // Запрос прошёл, а файл ещё не сохранился
                    sleep(1);
                }

                $this->assertNotEmpty(file_get_contents($filename), 'Client can not save output file');
            }
            $ts_6 = microtime(true);
            $console_output = file_get_contents($filename_console);

            $a = explode("\r\n\r\n", file_get_contents($filename), 2);
            unlink($filename_console);
            unlink($filename);
            if (count($a) == 2) {
                list(, $retr_body) = $a;
            } else {
                $retr_body = '';
            }
            unset($a);
            if ($expected_request_success) {
                $this->assertTrue(self::$request_success, 'Запрос не прошёл, хотя обязан был пройти');
                $this->assertEquals(isset($options['expected_body']) ? $options['expected_body'] : 'la tortuga: '.$port,
                    $retr_body);
            } else {
                $this->assertFalse(self::$request_success, 'Запрос прошёл, хотя обязан был не пройти');
                $this->assertEmpty($retr_body);
                if (isset($options['expected_error_code'])) {
                    $this->assertNotFalse(
                        strpos($console_output, ' ERROR '.$options['expected_error_code'].': '),
                        'Expected HTTP code #'.$options['expected_error_code'].' missed'
                    );
                }
                if (isset($options['expected_invalid_connection']) and $options['expected_invalid_connection']) {
                    $this->assertTrue(self::$request_invalid_connection, 'There was no malformed connection');
                }
            }
            self::$_server->shutdown();
            self::$_server = null;
            $ts_7 = microtime(true);
            self::$_testListeningScenario_bind[0] += $ts_2 - $ts_1;
            self::$_testListeningScenario_bind[1] += $ts_3 - $ts_2;
            self::$_testListeningScenario_bind[2] += $ts_4 - $ts_3;
            self::$_testListeningScenario_bind[3] += $ts_5 - $ts_4;
            self::$_testListeningScenario_bind[4] += $ts_6 - $ts_5;
            self::$_testListeningScenario_bind[5] += $ts_7 - $ts_6;
        }

        function dataConstruct_failed() {
            return [
                [
                    ['ssl_server_key_file' => '/dev/null'],
                ], [
                    ['ssl_server_key_password' => '/dev/null'],
                ], [
                    ['ssl_client_certificate_file' => '/dev/null'],
                ],
            ];
        }

        /**
         * @param array $server_settings
         *
         * @expectedException Exception
         * @dataProvider dataConstruct_failed
         */
        function testConstruct_failed(array $server_settings) {
            $port = self::get_port();
            $server_settings['port'] = $port;
            new Server($server_settings);
        }

        /**
         * @covers \NokitaKaze\TestHTTPServer\Server::get_option
         * @covers \NokitaKaze\TestHTTPServer\Server::set_option
         */
        function testGetterSetter() {
            $port = self::get_port();
            self::$_server = new Server((object) ['port' => $port]);
            $obj = $this;
            self::$_server->set_option('onRequest', function ($server, $connect) use ($obj, $port) {
                /** @var ClientDatum $connect */
                $connect->server->answer($connect, 200, 'OK', 'la tortuga: '.$port);

                self::$request_success = true;
                $obj->assertEquals('/', $connect->request_url, 'Request url mismatch');
                $obj->assertEquals('GET', $connect->request_type, 'Request type mismatch');
                $obj->assertTrue(
                    ('127.0.0.1:'.$port == $connect->request_head_params['Host']) or
                    ('127.0.0.1' == $connect->request_head_params['Host']),
                    'Request host mismatch'
                );

                $connect->status = 3;
            });
            self::$_server->set_option('foobar', 'nyanpasu');
            $this->assertEquals('nyanpasu', self::$_server->get_option('foobar'));
            self::$_server->init_listening();

            $filename = tempnam(self::$_folder, 'wget_output_');
            $filename_console = tempnam(self::$_folder, 'wget_console_');
            $wget_script = sprintf('wget "http://127.0.0.1:%d/" -O %s --save-headers > %s 2>&1 &',
                $port,
                escapeshellarg($filename),
                escapeshellarg($filename_console));
            exec($wget_script);
        }

        function dataHTTPerf() {
            return [
                [1, 60, 5, false],
                [1, 60, 20, true],
                [5, 60, 5, false],
                [5, 60, 20, true],
                [10, 10, 20, false],
                [10, 10, 20, true],
                [50, 10, 20, false],
                [50, 10, 20, true],
                [100, 20, 20, false],
                [100, 20, 20, true],
            ];
        }

        /**
         * @param integer $rate
         * @param integer $second
         * @param integer $timeout
         * @param boolean $is_ssl
         *
         * @dataProvider dataHTTPerf
         * @url https://media.readthedocs.org/pdf/yandextank/latest/yandextank.pdf
         */
        function testHTTPerf($rate, $second, $timeout, $is_ssl) {
            $port = self::get_port();
            $invalid_connection_count = 0;
            $max_connection_count = 0;
            self::$_server = new Server((object) [
                'interface' => '0.0.0.0',
                'port' => $port,
                'onRequest' => function ($server, $connect) use (&$max_connection_count) {
                    /** @var Server $server */
                    /** @var ClientDatum $connect */
                    $connect->server->answer($connect, 200, 'OK', 'Nyan pasu', [
                        'Content-type' => 'text/plain;',
                    ]);
                    $count = 0;
                    $reflection = new \ReflectionProperty($server, '_client_connects');
                    $reflection->setAccessible(true);
                    foreach ($reflection->getValue($server) as &$single_connect) {
                        /** @var ClientDatum $single_connect */
                        if (!is_null($single_connect) and !is_null($single_connect->client)) {
                            $count++;
                        }
                    }
                    $max_connection_count = max($max_connection_count, $count);

                    $connect->status = 3;
                },
                'InvalidConnection' => function ($server) use (&$invalid_connection_count, &$max_connection_count) {
                    $invalid_connection_count++;
                    $count = 0;
                    $reflection = new \ReflectionProperty($server, '_client_connects');
                    $reflection->setAccessible(true);
                    foreach ($reflection->getValue($server) as &$single_connect) {
                        /** @var ClientDatum $single_connect */
                        if (!is_null($single_connect) and !is_null($single_connect->client)) {
                            $count++;
                        }
                    }
                    $max_connection_count = max($max_connection_count, $count);
                },
            ]);
            if ($is_ssl) {
                self::$_server->set_option('is_ssl', true);
                self::$_server->stream_set_ssl_option('local_cert', self::$_folder.'/crt_a3.c.crt');
                self::$_server->stream_set_ssl_option('local_pk', self::$_folder.'/crt_a3.pem');
                self::$_server->stream_set_ssl_option('allow_self_signed', true);
                self::$_server->stream_set_ssl_option('verify_peer', false);
            }

            $folder = self::$_folder.'/yandex-tank-'.microtime(true);
            mkdir($folder);
            chdir($folder);
            $rate = (int) $rate;
            $number_calls = (int) ($second * $rate);
            file_put_contents($folder.'/load.ini', sprintf('[phantom]
address=%s:%d ;Target\'s address
ssl=%d
rps_schedule = const(%d, %ds) const(0, %ds) ;load scheme
headers = [Host: %s]
uris = /
timeout = %ds
instances = %d
',
                strtolower(gethostname()), $port,
                $is_ssl ? 1 : 0,
                $rate, $second, $timeout,
                strtolower(gethostname()), $timeout, min($rate * $timeout, 200)));

            $logs_directory = null;
            $phout_log_file = null;

            $filename_console = tempnam(self::$_folder, 'httperf_console_');
            $command = sprintf('yandex-tank > %s 2>/dev/null &', escapeshellarg($filename_console));
            self::$_server->init_listening();
            exec($command);
            $ts_stop = microtime(true) + $second + 60;
            $closure = function ($server) use (&$logs_directory, &$phout_log_file, $ts_stop, $folder) {
                $logs_directory = null;
                if (!file_exists($folder.'/logs')) {
                    return ($ts_stop >= microtime(true));
                }
                foreach (scandir($folder.'/logs') as $dir) {
                    if (preg_match('_^[0-9]+\\-[0-9]{2,2}\\-[0-9]{2,2}_', $dir) and is_dir($folder.'/logs/'.$dir)) {
                        $logs_directory = $folder.'/logs/'.$dir;
                        break;
                    }
                }
                if (is_null($logs_directory)) {
                    return ($ts_stop >= microtime(true));
                }
                foreach (scandir($logs_directory) as $f) {
                    if (preg_match('|^phout_.+\\.log$|', $f)) {
                        $phout_log_file = $logs_directory.'/'.$f;
                        break;
                    }
                }
                if (!is_null($phout_log_file)) {
                    return false;
                }

                return ($ts_stop >= microtime(true));
            };
            self::$_server->listen($closure);
            // $output_console = file_get_contents($filename_console);
            self::$_server->shutdown();
            self::$_server = null;

            $this->assertNotNull($logs_directory, 'Can not find directory with Yandex Tank\'s logs');
            $this->assertNotNull($phout_log_file, 'Can not find phout output log within Yandex Tank\'s logs');
            $strings = preg_split("_[\\r\\n]+_", file_get_contents($phout_log_file));
            $http_codes = [0, 0, 0, 0, 0, 0];
            foreach ($strings as $string) {
                if (empty($string)) {
                    continue;
                }
                list(, , , , , , , , , , , $http_code) = preg_split('_\\s+_', $string);
                $http_code = (int) $http_code;
                $http_codes[(int) floor($http_code / 100)]++;
            }
            $additional_log = '';
            if ($invalid_connection_count > 0) {
                $additional_log .= sprintf("\nInvalid connection count: %d", $invalid_connection_count);
            }
            if ($max_connection_count > 0) {
                $additional_log .= sprintf("\nPeak established connection count: %d", $max_connection_count);
            }

            if ($rate > 5) {
                if ($number_calls * ($is_ssl ? 0.90 : 1) <
                    $http_codes[1] + $http_codes[2] + $http_codes[3] + $http_codes[4] + $http_codes[5]
                ) {
                    $this->markTestIncomplete(sprintf('Connections count mismatch. %d sent, %d expected, %d retrieved%s',
                        $number_calls, $number_calls * ($is_ssl ? 0.90 : 1),
                        $http_codes[1] + $http_codes[2] + $http_codes[3] + $http_codes[4] + $http_codes[5], $additional_log));
                }
                if ($http_codes[1] + $http_codes[4] + $http_codes[5] > ($is_ssl ? 0.075 * $number_calls : 0)) {
                    $this->markTestIncomplete(sprintf('HTTP code: 1xx=%d, 4xx=%d, 5xx=%d%s',
                        $http_codes[1], $http_codes[4], $http_codes[5], $additional_log));
                }

                return;
            }
            $this->assertGreaterThanOrEqual($number_calls * ($is_ssl ? 0.90 : 0.97),
                $http_codes[1] + $http_codes[2] + $http_codes[3] + $http_codes[4] + $http_codes[5],
                'Connections count mismatch'.$additional_log);
            $this->assertLessThanOrEqual($is_ssl ? 0.05 * $number_calls : 0,
                $http_codes[1] + $http_codes[4] + $http_codes[5],
                sprintf('HTTP code: 1xx=%d, 4xx=%d, 5xx=%d%s', $http_codes[1], $http_codes[4], $http_codes[5], $additional_log)
            );
        }
    }

?>