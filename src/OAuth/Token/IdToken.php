<?php declare(strict_types = 1);

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
		'azp' => '',
		'at_hash' => '',
		'c_hash' => ''
	];

	/**
	 * @var string $idToken the undecoded ID Token
	 */
	protected $idToken = '';

	/**
	 * @var array $claims The claims contained in the ID token.
	 */
	protected $claims = [];

	/**
	 * Constructs an IdToken instance from an undecoded ID token string
	 *
	 * @param string $idToken the undecoded ID token string
	 */

	public function __construct(string $idToken) {
		$this->idToken = $idToken ?? '';
		$claims = (array)JWT::decode($idToken, 1);
		$this->claims = array_merge(self::CLAIMS, $claims);
		if (isset($claims['aud']) && is_array($claims['aud'])) {
			$this->claims['aud'] = $claims['aud'];
		}
		if (isset($claims['amr'])) {
			$this->claims['amr'] = $claims['amr'];
		}
	}

	/**
	 * Returns the undecoded ID Token
	 *
	 * @return string
	 */
	public function get() : string {
		return $this->idToken;
	}

	/**
	 * Returns the Issuer Identifier of the issuer of the response.
	 *
	 * The iss value is a case sensitive URL using the https scheme.
	 *
	 * @return string
	 */
	public function getIss() : string {
		return $this->claims['iss'];
	}

	/**
	 * Returns the Subject Identifier.
	 *
	 * This is a locally unique and never reassigned identifier within the Issuer
	 * for the End-User, which is intended to be consumed by the Client
	 *
	 * @return string
	 */
	public function getSub() : string {
		return $this->claims['sub'];
	}

	/**
	 * Returns the audience(s) that this ID Token is intended for.
	 *
	 * In the general case, the aud value is an array of case sensitive strings.
	 * In the common special case when there is one audience,
	 * the aud value may be a single case sensitive string.
	 *
	 * @return string|array
	 */
	public function getAud() {
		return $this->claims['aud'];
	}

	/**
	 * Returns the expiration time on or after which the ID Token MUST NOT be accepted for processing. 
	 *
	 * @return string
	 */
	public function getExp() : string {
		return $this->claims['exp'];
	}

	/**
	 * Returns the time at which the JWT was issued.
	 *
	 * @return string
	 */
	public function getIat() : string {
		return $this->claims['iat'];
	}

	/**
	 * Returns the time when the End-User authentication occurred.
	 *
	 * @return string
	 */
	public function getAuthTime() {
		return $this->claims['auth_time'];
	}

	/**
	 * Returns the value used to associate a Client session with an ID Token,
	 * and to mitigate replay attacks.
	 *
	 * @return string
	 */
	public function getNonce() : string {
		return $this->claims['nonce'];
	}

	/**
	 * Returns the Authentication Context Class Reference.
	 *
	 * @return string
	 */
	public function getAcr() : string {
		return $this->claims['acr'];
	}

	/**
	 * Returns the Authentication Methods References.
	 *
	 * @return array
	 */
	public function getAmr() : array {
		return $this->claims['amr'];
	}

	/**
	 * Returns the Authorized party - the party to which the ID Token was issued.
	 *
	 * @return string
	 */
	public function getAzp() : string {
		return $this->claims['azp'];
	}

	/**
	 * Returns the hash of the OAuth2 access token when used with Implicit profile.
	 *
	 * @return string
	 */
	public function getAtHash() : string {
		return $this->claims['at_hash'];
	}

	/**
	 * Returns the hash of the OAuth2 authorization code when used with the hybrid profile.
	 *
	 * @return string
	 */
	public function getCHash() : string {
		return $this->claims['c_hash'];
	}

	/**
	 * Returns the value of specified claim
	 *
	 * @param string the name of the claim
	 * @return string|array the value of the claim
	 */
	public function getClaim(string $claim) {
		return $this->claims[$claim] ?? '';
	}

	/**
	 * Returns the array of claims
	 *
	 * @return array
	 */
	public function getClaims() : array {
		return $this->claims;
	}

	/**
	 * Returns the undecoded ID Token
	 *
	 * Alias of the get method
	 *
	 * @return string
	 */
	public function __toString() : string {
		return $this->get();
	}

	/**
	 * Returns the array of claims
	 *
	 * Alias of the getClaims method
	 *
	 * @return array
	 */
	public function toArray() : array {
		return $this->getClaims();
	}


}