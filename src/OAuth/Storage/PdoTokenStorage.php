<?php

namespace eureka2\OAuth\Storage;

use eureka2\OAuth\Token\AccessToken;
use eureka2\OAuth\Exception\OAuthClientException;

class PdoTokenStorage
	extends AbstractTokenStorage 
	implements TokenStorageInterface, TokenStorageManagementInterface {

	private $pdo = null;

	public function createOAuthSession(&$session) {
		$session = null;
		$this->initializeOAuthSession($session);
		$parameters = [
			$session->getSessionId(), \PDO::PARAM_STR,
			$session->getState(), \PDO::PARAM_STR,
			$session->getNonce(), \PDO::PARAM_STR,
			$session->getProvider(), \PDO::PARAM_STR,
			$session->getCreation(), \PDO::PARAM_STR
		];
		if (!$this->query('INSERT INTO oauth_session (session, state, nonce, provider, creation) VALUES(?, ?, ?, ?, ?)', $parameters, $results)) {
			return false;
		}
		$session->setId($results);
		return true;
	}

	public function getOAuthSession($sessionId, $provider, &$oauthSession) {
		$parameters = [
			$sessionId, \PDO::PARAM_STR,
			$provider, \PDO::PARAM_STR
		];
		if (!$this->query('SELECT id, session, state, nonce, access_token, access_token_secret, expiry, authorized, type, provider, creation, refresh_token, id_token, access_token_response, user FROM oauth_session WHERE session=? AND provider=?', $parameters, $results)) {
			return false;
		}
		if (count($results) === 0) {
			$oauthSession = null;
			return true;
		}
		$this->setOAuthSession($oauthSession, $results[0]);
		return true;
	}

	public function saveOAuthSession($session) {
		$token = $session->getAccessToken();
		$parameters = [
			$session->getSessionId(), \PDO::PARAM_STR,
			$session->getState(), \PDO::PARAM_STR,
			$session->getNonce(), \PDO::PARAM_STR,
			$token->getValue(), \PDO::PARAM_STR,
			$token->getSecret(), \PDO::PARAM_STR,
			$token->getExpiry(), \PDO::PARAM_STR,
			$token->getAuthorized(), \PDO::PARAM_BOOL,
			$token->getType(), \PDO::PARAM_STR,
			$session->getProvider(), \PDO::PARAM_STR,
			$session->getCreation(), \PDO::PARAM_STR,
			$token->getRefresh(), \PDO::PARAM_STR,
			"".$token->getIdToken(), \PDO::PARAM_STR,
			json_encode($token->getResponse()), \PDO::PARAM_STR,
			$session->getUser(), \PDO::PARAM_STR,
			$session->getid(), \PDO::PARAM_INT
		];
		return $this->query('UPDATE oauth_session SET session=?, state=?, nonce=?, access_token=?, access_token_secret=?, expiry=?, authorized=?, type=?, provider=?, creation=?, refresh_token=?, id_token=?, access_token_response=?, user=? WHERE id=?', $parameters, $results);
	}

	public function resetAccessToken() {
		$provider = $this->client->getProvider()->getName();
		$this->client->trace('Resetting the access token status for OAuth provider ' . $provider);
		if (!empty($this->getSessionId()) || !empty($this->getSessionCookie())) {
			$sessionId = !empty($this->getSessionId()) ? $this->getSessionId() : $this->getSessionCookie();
			$parameters = [
				$sessionId, \PDO::PARAM_STR,
				$provider, \PDO::PARAM_STR
			];
			$results = 0;
			if (!$this->query('DELETE FROM oauth_session WHERE session=? AND provider=?', $parameters, $results)) {
				return false;
			}
		}
		$this->deleteSessionCookie();
		return true;
	}

	private function setOAuthSession(&$oauthSession, $session) {
		$accessToken = new AccessToken([
			'value' => $session[4],
			'secret' => $session[5],
			'expiry' => $session[6],
			'authorized' => $session[7],
			'type' => $session[8],
			'refresh' => $session[11],
			'id_token' => $session[12],
			'response' => (isset($session[13]) ? json_decode($session[13]) : null)
		]);
		$oauthSession = new OAuthSessionValue();
		$oauthSession->setId($session[0]);
		$oauthSession->setSession($session[1]);
		$oauthSession->setState($session[2]);
		$oauthSession->setNonce($session[3]);
		$oauthSession->setAccessToken($accessToken);
		$oauthSession->setProvider($session[9]);
		$oauthSession->setCreation($session[10]);
		$oauthSession->setUser($session[14]);
	}

	private function connect() {
		if (!isset($this->parameters['dsn'])) {
			throw new OAuthClientException('The database dsn is not provided');
		}
		try {
			if (isset($this->parameters['user'])) {
				if (isset($this->parameters['password'])) {
					$this->pdo = new \PDO(
						$this->parameters['dsn'],
						$this->parameters['user'],
						$this->parameters['password']
					);
				} else {
					$this->pdo = new \PDO($this->parameters['dsn'], $this->parameters['user']);
				}
			} else {
				$this->pdo = new \PDO($this->parameters['dsn']);
			}
		} catch (\PDOException  $e) {
			throw new OAuthClientException(
				sprintf(
					"Unable to connect to '%s', the error '%s' was returned.",
					$this->parameters['dsn'],
					$e->getMessage()
				)
			);
		}
	}

	private function query($sql, $parameters, &$results) {
		if (!isset($this->pdo)) {
			$this->connect();
		}
		try {
			$sth = $this->pdo->prepare($sql);
			if ($sth === false) {
				$this->client->trace("PDO prepare error: " . $sql . ' => ' . implode(' ', $this->pdo->errorInfo()));
				return false;
			}
			$nparameters = count($parameters);
			for ($i = 0; $i < $nparameters; $i += 2) {
				$sth->bindValue(($i / 2) + 1, $parameters[$i],  $parameters[$i + 1]);
			}
			if ($sth->execute() === false) {
				$this->client->trace("PDO execute error: " . $sql . ' => ' . implode(' ', $sth->errorInfo()));
				return false;
			}
			if (preg_match("/^INSERT /i", $sql)) {
				$results = $this->pdo->lastInsertId();
			} elseif (preg_match("/^SELECT /i", $sql)) {
				$results = [];
				while ($row = $sth->fetch(\PDO::FETCH_NUM)) {
					$results[] = $row;
				}
			} else {
				$results = $sth->rowCount();
			}
			return true;
		} catch (\PDOException  $e) {
			$this->client->trace("PDOException : " . $sql . ' => ' . $e->getMessage());
			return false;
		}
	}

}
