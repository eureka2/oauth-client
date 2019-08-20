<?php declare(strict_types = 1);

namespace eureka2\OAuth\Token;

use eureka2\OAuth\Exception\OAuthClientSignatureException;

/**
 *
 * This class provides a set of functions related to Json Web Token
 *
 * A JSON Web Token (JWT) includes three sections:
 * 0 - Header
 * 1 - Payload
 * 2 - Signature
 *
 * They are encoded as Base64url strings, and are separated by dot "." characters.
 *
 */
class JWT {

	/**
	 * Decodes a section of the JSON Web Token and returns it.
	 *
	 * @param string $jwt The string value of the JSON Web Token
	 * @param int $section the section number to decode (0 to 2)
	 * @param bool $object true if the decoded section must be returned as an object, false otherwise
	 *
	 * @ return object|string
	 */
	public static function decode(string $jwt, int $section = 0, bool $object = true) {
		$parts = explode('.', $jwt);
		$part = $parts[$section];
		$decoded = self::safeBase64Decode($part);
		return $object ? json_decode($decoded) : $decoded;
	}

	private static function safeBase64Decode(string $part) {
		$padding = strlen($part) % 4;
		if ($padding > 0) {
			$part .= str_repeat('=', 4 - $padding);
		}
		return base64_decode(strtr($part, '-_', '+/'));
	}

	private static function encodeASNLength(int $length) {
		if ($length <= 0x7F) {
			return chr($length);
		}
		$temp = ltrim(pack('N', $length), chr(0));
		return pack('Ca*', 0x80 | strlen($temp), $temp);
	}

	private static function getKeyForHeader($keys, $header) {
		foreach ($keys as $key) {
			if ($key->kty == 'RSA') {
				if (!isset($header->kid) || $key->kid == $header->kid) {
					return $key;
				}
			} else {
				if (isset($key->alg) && $key->alg == $header->alg && $key->kid == $header->kid) {
					return $key;
				}
			}
		}
		throw new OAuthClientSignatureException(
			'Unable to find a key for RSA'
		);
	}

	private static function createPemPublicKey($key) {
		$modulus = self::safeBase64Decode($key->n);
		$modulus = pack('Ca*a*', 2, self::encodeASNLength(strlen($modulus)), $modulus);
		$exponent = self::safeBase64Decode($key->e);
		$exponent = pack('Ca*a*', 2, self::encodeASNLength(strlen($exponent)), $exponent);
		$pemPublicKey = pack(
			'Ca*a*a*',
			48,
			self::encodeASNLength(strlen($modulus) + strlen($exponent)),
			$modulus,
			$exponent
		);
		$rsaOID = pack('H*', '300d06092a864886f70d0101010500');
		$pemPublicKey = chr(0) . $pemPublicKey;
		$pemPublicKey = chr(3) . self::encodeASNLength(strlen($pemPublicKey)) . $pemPublicKey;
		$pemPublicKey = pack(
			'Ca*a*',
			48,
			self::encodeASNLength(strlen($rsaOID . $pemPublicKey)),
			$rsaOID . $pemPublicKey
		);
		$pemPublicKey = "-----BEGIN PUBLIC KEY-----\r\n" .
			chunk_split(base64_encode($pemPublicKey), 64) .
			'-----END PUBLIC KEY-----';
		return $pemPublicKey;
	}

	public static function verifyRSASignature($header, $keys, string $jwt) {
		$encoded = explode('.', $jwt);
		$data = $encoded[0] . '.' .$encoded[1];
		$signature = self::decode($jwt, 2, false);
		$key = self::getKeyForHeader($keys, $header);
		$publicKey = self::createPemPublicKey($key);
		$publicKeyResource = openssl_pkey_get_public($publicKey);
		$algo = 'sha' . substr($header->alg, 2); 
		$result = openssl_verify($data, $signature, $publicKeyResource, $algo);
		if ($result === -1)	{
			$errors = [];
			while ($error = openssl_error_string()) {
				$errors[] = $error;
			}
			throw new OAuthClientSignatureException(
				sprintf(
					"Failed to verify signature: %s",
					implode("\n", $errors)
				)
			);
		}
		return (bool) $result;
	}

	public static function verifyHMACsignature($header, string $jwt, string $key) {
		$algo = 'sha' . substr($header->alg, 2); 
		$encoded = explode('.', $jwt);
		$data = $encoded[0] . '.' .$encoded[1];
		$expected = hash_hmac($algo, $data, $key, true);
		$signature = self::decode($jwt, 2, false);
		return hash_equals($signature, $expected);
	}

}
