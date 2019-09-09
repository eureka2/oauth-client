<?php declare(strict_types = 1);

namespace eureka2\OAuth\Response;

/**
 * Base class for all resource, represents the response of the callAPI method.
 *
 * It implements the Iterator interface to allow the use of the foreach statement.
 */
abstract class OAuthResponse implements \Iterator {

	/**
	 * The name of the provider
	 *
	 * @var string $provider
	 */
	private $provider = '';

	/**
	 * The properties of the resource
	 *
	 * @var array $values
	 */
	private $values = [];

	/**
	 * Constructs a OAuthResponse object
	 *
	 * @param string $provider the provider name.
	 * @param array|object $values the properties of the resource.
	 * @param array $mapping Match between OAuth client fields and fields returned by the provider.
	 */
	public function __construct($provider, $values, $mapping = []) {
		$this->provider = $provider;
		if (is_object($values)) {
			$values = (array)$values;
		}
		$mapping = array_flip(array_merge([ 'user_id_field' => 'sub' ], $mapping));
		foreach($values as $property => $value) {
			if (is_object($value)) {
				$value = (array)$value;
			}
			if (is_array($value)) {
				foreach($value as $vproperty => $vvalue) {
					$this->setPropertyValue($property . '.' . $vproperty, $vvalue, $mapping);
				}
			} else {
				$this->setPropertyValue($property, $value, $mapping);
			}
		}
	}

	/**
	 * Sets the value of a property
	 *
	 * @param string $property the property name.
	 * @param string $value the value of the property.
	 * @param array $mapping Match between OAuth client fields and fields returned by the provider.
	 */
	protected function setPropertyValue($property, $value, &$mapping) {
		if (isset($mapping[$property])) {
			$mapped = preg_replace("/_field$/", "", $mapping[$property]);
			$this->values[$mapped] = $value;
		} else {
			$property = str_replace('.', '_', $property);
			$this->values[$property] = $value;
		}
	}

	/**
	 * Returns the name of the provider
	 *
	 * @return string the provider name.
	 */
	public function getProvider() {
		return $this->provider;
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
	 * @return mixed|null the value of the property or null
	 */
	public function __call($method, $arguments) {
		$m = [];
		if (!preg_match("/^(get|is|has|should)(.+)$/", $method, $m)) {
			trigger_error(
				sprintf(
					'Unknown response method %s',
					$method
				),
				E_USER_NOTICE
			);
			return null;
		}
		if (isset($arguments) && count($arguments) > 0) {
			trigger_error(
				sprintf(
					"The method %s doesn't accept any argument : %s",
					$method,
					var_export($arguments, true)
				),
				E_USER_NOTICE
			);
		}
		$property = preg_replace_callback(
			'/([A-Z])/', 
			function($c) {
				return '_' . strtolower($c[1]);
			}, 
			lcfirst($m[2])
		);
		return $this->values[$property] ?? null;
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
