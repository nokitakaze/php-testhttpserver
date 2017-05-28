<?php

    namespace NokitaKaze\TestHTTPServer;

    /**
     * @property \Callable|null $onListenStart
     * @property \Callable|null $onConnect                   (waits for ClientDatum)
     * @property \Callable|null $onRequest                   (= onBodyReceived)
     * @property \Callable|null $onDisconnect
     * @property \Callable|null $onListenStop
     * @property \Callable|null $onAnyIncomingData
     * @property \Callable|null $onHeadIncomingData
     * @property \Callable|null $onBodyIncomingData
     * @property \Callable|null $onHeadReceived
     * @property \Callable|null $onHeadInvalidReceived
     * @property \Callable|null $onHostNotFound
     * @property \Callable|null $onInvalidConnection
     * @property \Callable|null $filterIncomingConnect
     *
     * @property integer        $port
     * @property string|null    $interface
     * @property boolean        $is_ssl
     *
     * @property double         $server_sleep_if_no_connect
     * @property double         $server_wait_before_first_byte
     * @property double         $server_maximum_chunk
     *
     * @property string|null    $ssl_server_certificate_file Certificate chain file for HTTPS domain
     * @property string|null    $ssl_server_key_file         Client pem-file
     * @property string         $ssl_server_key_password     Password for client pem-file
     * @property string|null    $ssl_client_certificate_file Testing CA for client pem
     *
     * @property double         $time_wait_until_first_byte
     * @property double         $time_wait_until_head_received
     * @property double         $time_wait_until_request_received
     * @property double         $time_between_head_and_body_received
     */
    interface ServerSettings {
    }

    /**
     * @property string|null     $host                        Куда мы подключаемся
     * @property string|null     $domain                      Домен, который запрашиваем
     * @property integer         $port
     * @property boolean         $is_ssl
     *
     *
     * @property string|null     $ssl_server_certificate_file Certificate chain file for HTTPS domain
     * @property string|null     $ssl_client_certificate_file Testing CA for client pem
     * @property string|null     $ssl_client_key_file         Client pem-file
     * @property string          $ssl_client_key_password     Password for client pem-file
     *
     * @property string          $head
     * @property string          $body
     * @property string          $answer
     *
     * @property integer         $scenario                    Номер сценария
     * @property string          $output_filename
     *
     * @property double          $interval_before_body
     * @property double          $interval_before_head
     * @property double|double[] $body_byte_per_interval
     * @property double|double[] $body_interval
     * @property double|double[] $head_byte_per_interval
     * @property double|double[] $head_interval
     * @property boolean         $at_once
     */
    interface BorgSettings {
    }

    /**
     * @property resource      $client
     * @property integer       $status                             (0 — ждём голову, 1 — ждём тело, 2 — тело и голова приняты)
     * @property double        $connection_time
     *
     * @property double|null   $head_received_time
     * @property double|null   $body_received_time
     * @property double|null   $full_request_received_time         max(head_received_time, body_received_time)
     * @property double|null   $last_byte_received_time
     * @property double|null   $first_byte_received_time
     *
     * @property string        $blob_request
     * @property string        $blob_head
     * @property string        $blob_body
     * @property string        $request_url
     * @property string        $request_type
     * @property string        $request_http_version
     * @property array         $request_head_params                Параметры из головы
     * @property Server        $server
     *
     * @property array         $context_options
     * @property array         $context_params
     *
     * @property string[]|null $accepted_hosts
     */
    interface ClientDatum {
    }

?>