<?php

namespace eureka2\OAuth\Token;

use eureka2\OAuth\Exception\OAuthClientSignatureException;

class JWT {

	public static function decode($jwt, $section = 0, $json = true) {
		$parts = explode('.', $jwt);
		$part = $parts[$section];
		$decoded = self::safeBase64Decode($part);
		return $json ? json_decode($decoded) : $decoded;
	}

	private static function safeBase64Decode($part) {
		$padding = strlen($part) % 4;
		if ($padding > 0) {
			$part .= str_repeat('=', 4 - $padding);
		}
		return base64_decode(strtr($part, '-_', '+/'));
	}

	private static function encodeASNLength($length) {
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

	public static function verifyRSASignature($header, $keys, $jwt) {
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

	public static function verifyHMACsignature($header, $jwt, $key) {
		$algo = 'sha' . substr($header->alg, 2); 
		$encoded = explode('.', $jwt);
		$data = $encoded[0] . '.' .$encoded[1];
		$expected = hash_hmac($algo, $data, $key, true);
		$signature = self::decode($jwt, 2, false);
		return hash_equals($signature, $expected);
	}

}
