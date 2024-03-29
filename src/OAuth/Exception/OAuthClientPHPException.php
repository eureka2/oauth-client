<?php

/*
 * This file is part of the eureka2/oauth-client library.
 *
 * Copyright (c) 2019 Jacques Archimède
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace eureka2\OAuth\Exception;

class OAuthClientPHPException extends OAuthClientException {

	public function __construct($message = null, $code = 0) {
		$error = error_get_last();
		if (isset($error)) {
			$message .= ": " . $error['message'];
		}
		parent::__construct($message, $code);
	}

	public function __toString() {
		return 	get_class($this) . 
				" '{$this->message}' in {$this->file}({$this->line})\n" . 
				"{$this->getTraceAsString()}";
	}

}
