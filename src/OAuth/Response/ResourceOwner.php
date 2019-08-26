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

	/**
	 * The ID of the resource owner
	 *
	 * @var string $id;
	 */
	private $id = '';

	/**
	 * Constructs a ResourceOwner object
	 *
	 * @param string $id The ID of the resource owner
	 * @param array $values The properties of the resource owner
	 */
	public function __construct($id, $values) {
		$this->id = $id;
		parent::__construct($values);
	}

	/**
	 * Resourns the ID of the resource owner
	 *
	 * @return string;
	 */
	public function getId() {
		return $this->id;
	}

}
