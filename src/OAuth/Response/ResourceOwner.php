<?php declare(strict_types = 1);

namespace eureka2\OAuth\Response;

/**
 * This class represents a resource owner
 *
 * The resource owner is the user who authorizes an application to access their account.
 * The application’s access to the user’s account is limited to the “scope” of the authorization granted 
 *
 */
class ResourceOwner extends OAuthResponse {

	const ADDRESS_MAPPING = [
		'street_address' => 'address.street_address',
		'postal_code' => 'address.postal_code',
		'locality' => 'address.locality',
		'region' => 'address.region',
		'country' => 'address.country',
		'formatted' => 'address.formatted'
	];

	/**
	 * The ID of the resource owner
	 *
	 * @var string $id;
	 */
	private $id = '';

	/**
	 * Constructs a ResourceOwner object
	 *
	 * @param string $property the property name.
	 * @param string $id The ID of the resource owner
	 * @param array $values The properties of the resource owner
	 * @param array $mapping Match between OAuth client fields
	 * and fields returned by the provider's UserInfo endpoint.
	 */
	public function __construct($provider, $id, $values, $mapping) {
		$this->id = $id;
		parent::__construct($provider, $values, array_merge(self::ADDRESS_MAPPING, $mapping));
	}

	/**
	 * Returns the ID of the resource owner
	 *
	 * @return string the ID of the resource owner
	 */
	public function getId() {
		return $this->id;
	}

}
