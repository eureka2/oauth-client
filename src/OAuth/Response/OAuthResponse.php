<?php

namespace eureka2\OAuth\Response;

class OAuthResponse implements \Iterator {

	private $values = [];

	public function __construct($values) {
		$this->values = is_object($values) ? (array)$values : $values;
	}

	public function __get($property) {
		if (array_key_exists($property, $this->values)) {
			return $this->values[$property];
		}
		$trace = debug_backtrace();
		trigger_error(
			sprintf(
				'Unknown response property %s in line %s of %s',
				$property,
				$trace[0]['line'],
				$trace[0]['file']
			),
			E_USER_NOTICE
		);
		return null;
	}

	public function __isset($property) {
		return isset($this->values[$property]);
	}

	public function __call($method, $arguments) {
		$m = [];
		if (!preg_match("/^get(.+)$/", $method, $m)) {
			trigger_error(
				sprintf(
					'Unknown response method %s',
					$method
				),
				E_USER_NOTICE
			);
			return null;
		}
		if (isset($arguments)) {
			trigger_error(
				sprintf(
					"The method %s doesn't accept any argument",
					$method
				),
				E_USER_NOTICE
			);
		}
		$property = preg_replace_callback(
			'/([A-Z])/', 
			function($c) {
				return '_' . strtolower($c[1]);
			}, 
			lcfirst($m[1])
		);
		return $this->values[$property];
	}

	public function rewind() {
		return reset($this->values);
	}

	public function current() {
		return current($this->values);
	}

	public function key() {
		return key($this->values);
	}

	public function next() {
		return next($this->values);
	}

	public function valid() {
		return key($this->values) !== null;
	}

}
