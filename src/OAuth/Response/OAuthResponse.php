<?php declare(strict_types = 1);

namespace eureka2\OAuth\Response;

/**
 * Base class for all resource, represents the response of the callAPI method.
 *
 * It implements the Iterator interface to allow the use of the foreach statement.
 */
abstract class OAuthResponse implements \Iterator {

	/**
	 * The properties of the resource
	 *
	 * @var array $values
	 */
	private $values = [];

	/**
	 * Constructs a OAuthResponse object
	 *
	 * @param array|object $values the properties of the resource.
	 */
	public function __construct($values) {
		$this->values = is_object($values) ? (array)$values : $values;
	}

	/**
	 * Allows direct read-only access to a property
	 *
	 * @param string $property the name of the property.
	 *
	 * @return mixed|null the value of the property or null if the propery doesn't exists.
	 */
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

	/**
	 * Allows to test (isset) directly the existence of a property
	 *
	 * @param string $property the name of the property.
	 *
	 * @return bool true if the property exists, false otherwise
	 */
	public function __isset($property) {
		return isset($this->values[$property]);
	}

	/**
	 * Defines a dynamic getter for the properties.
	 * For example, if the property is named 'my_property',
	 * a call to the getMyProperty() method will get the value of my_property.
	 *
	 * @param string $method the name of the getter.
	 * @param array $arguments arguments passed to the getter, ignored.
	 *
	 * @return bool true if the property exists, false otherwise
	 */
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

	/**
	 * Rewinds back to the first property of the resource.
	 */
	public function rewind() {
		reset($this->values);
	}

	/**
	 *  Returns the current property
	 *
	 * @return mixed the current property
	 */
	public function current() {
		return current($this->values);
	}

	/**
	 *  Returns the name of the current property
	 *
	 * @return scalar the name of the current property
	 */
	public function key() {
		return key($this->values);
	}

	/**
	 *  Moves forward to next property
	 */
	public function next() {
		next($this->values);
	}

	/**
	 *  Checks if current position is valid
	 *
	 * @return bool true if current position is valid
	 */
	public function valid() {
		return key($this->values) !== null;
	}

}
