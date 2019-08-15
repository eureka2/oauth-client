<?php

namespace eureka2\OAuth\Token;

class IdToken {

	const CLAIMS = [
		'iss' => '',
		'sub' => '',
		'aud' => '',
		'exp' => '',
		'iat' => '',
		'auth_time' => null,
		'nonce' => '',
		'acr' => '',
		'amr' => [],
		'azp' => ''
	];

	/**
	 * @var string
	 */
	protected $idToken = '';

	/**
	 * @var array
	 */
	protected $claims = [];

	public function __construct($idToken) {
		$this->idToken = $idToken ?? '';
		$claims = JWT::decode($idToken, 1);
		$this->claims = array_merge(self::CLAIMS, (array)$claims);
	}

	public function get() {
		return $this->idToken;
	}

	public function getIss() {
		return $this->claims['iss'];
	}

	public function getSub() {
		return $this->claims['sub'];
	}

	public function getAud() {
		return $this->claims['aud'];
	}

	public function getExp() {
		return $this->claims['exp'];
	}

	public function getIat() {
		return $this->claims['iat'];
	}

	public function getAuthTime() {
		return $this->claims['auth_time'];
	}

	public function getNonce() {
		return $this->claims['nonce'];
	}

	public function getAcr() {
		return $this->claims['acr'];
	}

	public function getAmr() {
		return $this->claims['amr'];
	}

	public function getAzp() {
		return $this->claims['azp'];
	}

	public function getClaim($claim) {
		return $this->claims[$claim] ?? '';
	}

	public function getClaims() {
		return $this->claims;
	}

		public function setIss($iss) {
		$this->claims['iss'] = $iss;
		return $this;
	}

	public function setSub($sub) {
		$this->claims['sub'] = $sub;
		return $this;
	}

	public function setAud($aud) {
		$this->claims['aud'] = $aud;
		return $this;
	}

	public function setExp($exp) {
		$this->claims['exp'] = $exp;
		return $this;
	}

	public function setIat($iat) {
		$this->claims['iat'] = $iat;
		return $this;
	}

	public function setAuthTime($auth_time) {
		$this->claims['auth_time'] = $auth_time;
		return $this;
	}

	public function setNonce($nonce) {
		$this->claims['nonce'] = $nonce;
		return $this;
	}

	public function setAcr($acr) {
		$this->claims['acr'] = $acr;
		return $this;
	}

	public function setAmr($amr) {
		$this->claims['amr'] = $amr;
		return $this;
	}

	public function setAzp($azp) {
		$this->claims['azp'] = $azp;
		return $this;
	}

	public function setClaim($claim, $value) {
		$this->claims[$claim] = $value;
		return $this;
	}

	public function __toString() {
		return $this->get();
	}

	public function toArray() {
		return $this->getClaims();
	}


}