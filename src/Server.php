<?php

    namespace NokitaKaze\TestHTTPServer;

    /**
     * Class Server
     * @package NokitaKaze\TestHTTPServer
     *
     * @doc https://tools.ietf.org/html/rfc7230
     * @doc http://httpwg.org/specs/rfc7230.html
     */
    class Server {
        const CHUNK_SIZE = 4096;

        /**
         * @var ServerSettings
         */
        protected $_settings = null;

        /**
         * @var resource
         */
        protected $_server_socket = null;

        /**
         * @var resource
         */
        protected $_stream_context = null;

        /**
         * @var ClientDatum[]
         */
        protected $_client_connects = [];

        /**
         * Server constructor
         *
         * @param ServerSettings|object|array $settings
         *
         * @throws Exception
         */
        function __construct($settings) {
            $settings = (object) $settings;
            self::fix_incoming_settings($settings);
            $this->_settings = $settings;
            $this->_stream_context = stream_context_create();
            if (isset($this->_settings->ssl_server_certificate_file)) {
                $this->stream_set_ssl_option('local_cert', $this->_settings->ssl_server_certificate_file);
                $this->stream_set_ssl_option('allow_self_signed', true);
                $this->stream_set_ssl_option('verify_peer', false);
                if (isset($this->_settings->ssl_server_key_file)) {
                    $this->stream_set_ssl_option('local_pk', $this->_settings->ssl_server_key_file);
                }
                $this->stream_set_ssl_option('passphrase',
                    isset($this->_settings->ssl_server_key_password) ? $this->_settings->ssl_server_key_password : '');

                if (isset($this->_settings->ssl_client_certificate_file)) {
                    $this->stream_set_ssl_option('verify_peer', true);
                    $this->stream_set_ssl_option('capture_peer_cert', true);
                    $this->stream_set_ssl_option('capture_peer_cert_chain', true);
                    $this->stream_set_ssl_option('cafile', $this->_settings->ssl_client_certificate_file);
                }
            } elseif (isset($this->_settings->ssl_server_key_file)) {
                throw new Exception('ssl_server_key_file is set, but ssl_server_certificate_file is missing');
            } elseif (isset($this->_settings->ssl_server_key_password)) {
                throw new Exception('ssl_server_key_password is set, but ssl_server_certificate_file is missing');
            } elseif (isset($this->_settings->ssl_client_certificate_file)) {
                throw new Exception('ssl_client_certificate_file is set, but ssl_server_certificate_file is missing');
            }
        }

        function __destruct() {
            $this->shutdown();
        }

        function shutdown() {
            foreach ($this->_client_connects as &$connect) {
                $this->close_connection($connect);
            }
            $this->_client_connects = [];
            $this->close_connection_socket($this->_server_socket);
        }

        /**
         * @param resource $connection
         */
        function close_connection_socket($connection) {
            if (is_resource($connection)) {
                fclose($connection);
            }
        }

        /**
         * @param object|ClientDatum $connection
         */
        function close_connection(&$connection) {
            if (is_null($connection)) {
                return;
            }
            $this->close_connection_socket($connection->client);
            $connection->client = null;
            $connection = null;
        }

        /**
         * @return array
         */
        static function get_default_settings() {
            return [
                'interface' => '127.0.0.1',
                'port' => 58080,
                'server_sleep_if_no_connect' => 1,
                'is_ssl' => false,
                'filterIncomingConnect' => function () { return true; },
                'server_maximum_chunk' => 300 * 1024,

                'time_wait_until_first_byte' => 60,
            ];
        }

        /**
         * Server constructor.
         *
         * @param ServerSettings|object $settings
         */
        protected static function fix_incoming_settings($settings) {
            $default_settings = self::get_default_settings();
            foreach ($default_settings as $key => $value) {
                if (!isset($settings->{$key})) {
                    $settings->{$key} = $value;
                }
            }
            foreach (['ListenStart', 'Connect', 'Request', 'Disconnect', 'ListenStop', 'AnyIncomingData', 'HeadIncomingData',
                      'BodyIncomingData', 'HeadReceived', 'HeadInvalidReceived'] as $event) {
                if (!isset($settings->{'on'.$event})) {
                    $settings->{'on'.$event} = null;
                }
            }
        }

        /**
         * @codeCoverageIgnore
         */
        function listen() {
            $this->init_listening();
            while (true) {
                $this->listen_tick();
            }
        }

        function init_listening() {
            $this->_server_socket = stream_socket_server(
                sprintf('%s://%s:%d',
                    $this->_settings->is_ssl ? 'ssl' : 'tcp',
                    is_null($this->_settings->interface) ? '0.0.0.0' : $this->_settings->interface,
                    $this->_settings->port
                ),
                $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN,
                $this->_stream_context);
            if (!isset($this->_server_socket)) {
                // @codeCoverageIgnoreStart
                throw new Exception('Can not create socket ['.$errstr.']', 100 + $errno);
                // @codeCoverageIgnoreEnd
            }

            $this->event_raise('ListenStart');
        }

        function listen_tick() {
            $read = [$this->_server_socket];
            $write = null;
            $except = null;
            if (stream_select($read, $write, $except, 0) === false) {
                // @codeCoverageIgnoreStart
                throw new Exception('Error on stream select');
                // @codeCoverageIgnoreEnd
            }
            if (empty($read)) {
                $ts_before = microtime(true);
                $this->process_all_connected_clients();
                $sleep = $this->_settings->server_sleep_if_no_connect - microtime(true) + $ts_before;
                if ($sleep > 0) {
                    usleep($sleep * 1000000);
                }

                return;
            }

            $client = @stream_socket_accept($this->_server_socket);
            if ($client === false) {
                $this->event_raise('InvalidConnection');

                // Если я не запущу process_all_connected_clients, то может быть DDoS через неправильные коннекты
                $this->process_all_connected_clients();

                return;
            }

            if (stream_set_blocking($client, 0) === false) {
                // @codeCoverageIgnoreStart
                throw new Exception('Can not set socket as non blocking');
                // @codeCoverageIgnoreEnd
            }
            $connect_time = microtime(true);
            /**
             * @var ClientDatum $datum
             */
            $datum = new \stdClass();
            $datum->status = 0;
            $datum->client = $client;
            $datum->connection_time = $connect_time;
            $datum->blob_request = '';
            $datum->request_head_params = [];
            $datum->server = $this;
            $datum->accepted_hosts = null;
            $this->event_raise('Connect', $datum);
            $this->_client_connects[] = $datum;

            //
            $this->process_all_connected_clients();
        }

        function stream_set_ssl_option($key, $value) {
            stream_context_set_option($this->_stream_context, 'ssl', $key, $value);
        }

        function set_option($key, $value) {
            $this->_settings->{$key} = $value;
        }

        function get_option($key) {
            return $this->_settings->{$key};
        }

        /**
         * Первый байт не пришёл
         *
         * @param object|ClientDatum $connection
         *
         * @return boolean
         */
        protected function check_timeouts_on_connection_first_byte($connection) {
            return isset($this->_settings->time_wait_until_first_byte) and
                   !isset($connection->first_byte_received_time) and
                   ($connection->connection_time < microtime(true) - $this->_settings->time_wait_until_first_byte);
        }

        /**
         * Голова не пришла
         *
         * @param object|ClientDatum $connection
         *
         * @return boolean
         */
        protected function check_timeouts_on_connection_head_received($connection) {
            return isset($this->_settings->time_wait_until_head_received) and
                   !isset($connection->head_received_time) and
                   ($connection->connection_time < microtime(true) - $this->_settings->time_wait_until_head_received);
        }

        /**
         * Запрос не пришёл
         *
         * @param object|ClientDatum $connection
         *
         * @return boolean
         */
        protected function check_timeouts_on_connection_request_received($connection) {
            return isset($this->_settings->time_wait_until_request_received) and
                   !isset($connection->full_request_received_time) and
                   ($connection->connection_time < microtime(true) - $this->_settings->time_wait_until_request_received);
        }

        /**
         * Тело не пришло (голова пришла)
         *
         * @param object|ClientDatum $connection
         *
         * @return boolean
         */
        protected function check_timeouts_on_connection_body_received_without_head($connection) {
            return isset($this->_settings->time_between_head_and_body_received, $connection->head_received_time) and
                   !isset($connection->full_request_received_time) and
                   ($connection->head_received_time < microtime(true) - $this->_settings->time_between_head_and_body_received);
        }

        /**
         * Проверяем слишком старые подключения и убиваем их
         *
         * @param object|ClientDatum $connection
         *
         * @return bool
         */
        protected function check_timeouts_on_connection(&$connection) {
            if ($this->check_timeouts_on_connection_first_byte($connection) or
                $this->check_timeouts_on_connection_head_received($connection) or
                $this->check_timeouts_on_connection_request_received($connection) or
                $this->check_timeouts_on_connection_body_received_without_head($connection)
            ) {
                $this->close_connection($connection);

                return false;
            }

            // @hint No Slowloris ( https://en.wikipedia.org/wiki/Slowloris_%28computer_security%29 ) test.
            // This is not a real server

            return true;
        }

        /**
         * Processing all connected clients
         */
        protected function process_all_connected_clients() {
            if (empty($this->_client_connects)) {
                return;
            }

            /**
             * @var resource[] $read
             * @var resource[] $write
             * @var resource[] $except
             */
            $read = [];
            foreach ($this->_client_connects as $connected) {
                if (is_null($connected)) {
                    continue;
                }
                if (is_null($connected->client)) {
                    $connected = null;
                    continue;
                }

                if (!is_resource($connected->client)) {
                    // @codeCoverageIgnoreStart
                    throw new Exception(sprintf('Connection became non resource: %s', (string) $connected->client));
                    // @codeCoverageIgnoreEnd
                }

                // Проверяем слишком старые подключения и убиваем их
                if (!$this->check_timeouts_on_connection($connected)) {
                    continue;
                }

                $read[] = $connected->client;
            }
            if (empty($read)) {
                $this->_client_connects = [];

                return;
            }
            $write = null;
            $except = null;
            if (stream_select($read, $write, $except, 0) === false) {
                // @codeCoverageIgnoreStart
                throw new Exception('Error on stream select');
                // @codeCoverageIgnoreEnd
            }
            unset($connected);

            foreach ($read as &$socket_resource) {
                foreach ($this->_client_connects as &$connected) {
                    if (!is_null($connected) and ($connected->client == $socket_resource)) {
                        $this->process_connected_client($connected);
                        break;
                    }
                }
            }
        }

        /**
         * @param ClientDatum $connect
         * @param double      $time
         * @param string      $buf
         *
         * @return boolean
         */
        protected function receive_data_from_connected_client($connect, $time, &$buf) {
            $buf = fread($connect->client, self::CHUNK_SIZE);
            if (empty($buf)) {
                $this->close_connection($connect);

                return false;
            }
            $connect->last_byte_received_time = $time;
            if (!isset($connect->first_byte_received_time)) {
                $connect->first_byte_received_time = $time;
            }
            if (strlen($buf) >= self::CHUNK_SIZE) {
                do {
                    $sub_buf = fread($connect->client, self::CHUNK_SIZE);
                    $buf .= $sub_buf;
                    if (isset($this->_settings->server_maximum_chunk) and
                        (strlen($buf) >= $this->_settings->server_maximum_chunk)
                    ) {
                        // Слишком много пришло за один раз
                        break;
                    }
                } while (strlen($sub_buf) >= self::CHUNK_SIZE);
            }

            return true;
        }

        /**
         * Processing all connected clients
         *
         * @param ClientDatum $connect
         */
        protected function process_connected_client(&$connect) {
            $time = microtime(true);
            $connect->context_options = stream_context_get_options($connect->client);
            $connect->context_params = stream_context_get_params($connect->client);
            if (!$this->receive_data_from_connected_client($connect, $time, $buf)) {
                $this->close_connection($connect);

                return;
            }
            $this->event_raise('AnyIncomingData', $connect, $buf);
            if ($connect->status == 0) {
                $this->event_raise('HeadIncomingData', $connect, $buf);
            } elseif ($connect->status == 1) {
                $this->event_raise('BodyIncomingData', $connect, $buf);
            }
            $connect->blob_request .= $buf;
            if (strpos($connect->blob_request, "\r\n\r\n") === false) {
                // Head не дошёл
                return;
            }

            // Проверяем на голову
            // Голова только-только дошла
            if (($connect->status == 0) and !$this->process_connected_client_head($connect, $time)) {
                return;
            }

            // Проверяем на body
            if ($connect->status == 1) {
                $this->process_connected_client_body($connect, $buf, $time);
            }
            if (is_null($connect) or ($connect->status != 2)) {
                return;
            }

            // Проверяем, что Host в списке обрабатываемых
            if (!$this->check_requested_host_in_accepted_list($connect)) {
                return;
            }

            // filterIncomingConnect
            $closure = $this->_settings->filterIncomingConnect;
            if (!$closure($this, $connect)) {
                $this->close_connection($connect);

                return;
            }
            unset($closure, $buf);

            // Request
            $this->event_raise('Request', $connect);

            if ($connect->status == 3) {
                $this->close_connection($connect);
            }
        }

        function check_requested_host_in_accepted_list($connect) {
            if (!isset($this->_settings->accepted_hosts)) {
                return true;
            }

            list($host) = explode(':', $connect->request_head_params['Host']);
            if (!in_array(strtolower($host), $this->_settings->accepted_hosts)) {
                if ($this->event_raise('HostNotFound', $connect) === false) {
                    $this->close_connection($connect);

                    return false;
                }

                $this->answer($connect, 404, 'Not Found', 'Host not found');
                $this->close_connection($connect);

                return false;
            }

            return true;
        }

        /**
         * If returns "false" connection closed
         *
         * @param ClientDatum $connect
         * @param double      $time
         *
         * @return boolean
         */
        protected function process_connected_client_head(&$connect, $time) {
            $connect->head_received_time = $time;
            list($connect->blob_head) = explode("\r\n\r\n", $connect->blob_request, 2);
            $a = explode("\r\n", $connect->blob_head, 2);
            list($first_line, $other_lines) = (count($a) == 2) ? $a : [$a[0], ''];
            if (!preg_match('_^([A-Z]+)\\s+(.+)\\s+HTTP/([0-9.]+)$_', $first_line, $a)) {
                if ($this->event_raise('HeadInvalidReceived', $connect, 0) === false) {
                    // Подключение сдохло
                    $this->close_connection($connect);

                    return false;
                }

                $this->answer($connect, 400, 'Bad Request', "This is not a HTTP request");
                $this->close_connection($connect);

                return false;
            }

            $connect->request_type = $a[1];
            $connect->request_url = $a[2];
            $connect->request_http_version = $a[3];
            if ($connect->request_type == 'POST') {
                $connect->status = 1;
            } elseif ($connect->request_type == 'GET') {
                $connect->status = 2;
                $connect->full_request_received_time = $time;
            } else {
                if ($this->event_raise('HeadInvalidReceived', $connect, 1) === false) {
                    // Подключение сдохло
                    $this->close_connection($connect);

                    return false;
                }

                $this->answer($connect, 400, 'Bad Request', "Can not process this request type");
                $this->close_connection($connect);

                return false;
            }

            $connect->request_head_params = [];
            foreach (explode("\r\n", $other_lines) as $other_line) {
                if (empty($other_line) or !preg_match('_^([A-Za-z0-9-]+):\\s*(.*)$_', $other_line, $a)) {
                    if ($this->event_raise('HeadInvalidReceived', $connect, 2) === false) {
                        // Подключение сдохло
                        $this->close_connection($connect);

                        return false;
                    }

                    $this->answer($connect, 400, 'Bad Request', "Malformed head");
                    $this->close_connection($connect);

                    return false;
                }

                $connect->request_head_params[$a[1]] = $a[2];
            }

            if (!isset($connect->request_head_params['Host'])) {
                $this->answer($connect, 400, 'Bad Request', "Field 'host' missed");
                $this->close_connection($connect);

                return false;
            }

            // event
            $this->event_raise('HeadReceived', $connect);

            return true;
        }

        /**
         * If returns "false" connection closed
         *
         * @param ClientDatum $connect
         * @param string      $buf
         * @param double      $time
         */
        protected function process_connected_client_body(&$connect, $buf, $time) {
            $head_end = strpos($connect->blob_request, "\r\n\r\n");
            if (!isset($connect->request_head_params['Content-Length'])) {
                if ($this->event_raise('HeadInvalidReceived', $connect, 3) === false) {
                    $this->close_connection($connect);

                    return;
                }

                $this->answer($connect, 400, 'malformed request', 'Malformed request');
                $this->close_connection($connect);

                return;
            }
            $requested_body_length = (int) $connect->request_head_params['Content-Length'];
            if (strlen($connect->blob_request) >= $head_end + 4 + $requested_body_length) {
                $connect->blob_body = substr($connect->blob_request, $head_end + 4, $requested_body_length);
                $connect->status = 2;
                $connect->body_received_time = $time;
                $connect->full_request_received_time = $time;
                // @hint Request raised in process_connected_client
            }

            $this->event_raise('BodyIncomingData', $connect, $buf);
        }

        /**
         * @param string $event
         *
         * @return mixed|null
         */
        function event_raise($event) {
            $method_name = 'on'.$event;
            if (!isset($this->_settings->{$method_name}) or !is_callable($this->_settings->{$method_name})) {
                return null;
            }

            $args = func_get_args();
            $args[0] = $this;

            return call_user_func_array($this->_settings->{$method_name}, $args);
        }

        /**
         * @param ClientDatum $connect
         * @param integer     $code
         * @param string      $code_text
         * @param string      $body
         * @param array       $headers
         */
        function answer($connect, $code, $code_text, $body, array $headers = []) {
            $buf = sprintf("HTTP/1.0 %d %s\r\n", $code, $code_text);
            $headers['Content-Length'] = strlen($body);
            foreach ($headers as $key => &$value) {
                $buf .= sprintf("%s: %s\r\n", $key, $value);
            }
            fwrite($connect->client, "{$buf}\r\n{$body}");
        }
    }

?>