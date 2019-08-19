<?php

namespace eureka2\OAuth\Response;

class ResourceOwner extends OAuthResponse {

	private $id = '';

	public function __construct($id, $values) {
		$this->id = $id;
		parent::__construct($values);
	}

	public function getId() {
		return $this->id;
	}

}
