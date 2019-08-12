<?php

spl_autoload_register(function ($class) {
	$prefixes = ['eureka2\\OAuth\\'];
	foreach($prefixes as $prefix) {
		if (strpos($class, $prefix) === 0) {
			$filename = str_replace('\\', DIRECTORY_SEPARATOR, substr($class, strlen($prefix))) . '.php';
			$fullpath = __DIR__ . DIRECTORY_SEPARATOR . $filename;
			if (file_exists($fullpath)) {
				/** @noinspection PhpIncludeInspection */
				require_once $fullpath;
				break;
			}
		}
	}
});
