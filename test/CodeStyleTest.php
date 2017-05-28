<?php

    namespace NokitaKaze\TestHTTPServer;

    class CodeStyleTest extends \PHPUnit_Framework_TestCase {
        function dataFolder() {
            $data = [];
            foreach ([__DIR__.'/../src', __DIR__.'/../test'] as $folder) {
                foreach (scandir($folder) as $d) {
                    if (!preg_match('_\\.php$_', $d)) {
                        continue;
                    }
                    $data[] = [
                        'filename' => $folder.'/'.$d,
                    ];
                }
            }

            return $data;
        }

        /**
         * @param string $filename
         *
         * @coversNothing
         * @dataProvider dataFolder
         */
        function testFilename($filename) {
            $buf = file_get_contents($filename);
            $this->assertNotContains("\r\n", $buf);
            $lines = explode("\n", $buf);
            $this->assertEquals('?>', $lines[count($lines) - 1]);
        }
    }

?>