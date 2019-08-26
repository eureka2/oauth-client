<?php declare(strict_types = 1);

namespace eureka2\OAuth\Storage;

use eureka2\OAuth\Token\AccessToken;
use eureka2\OAuth\Exception\OAuthClientException;

/**
 *
 * This class uses a PDO database (MySQL, PostGreSQL or SQLite)
 * to store the OAuth session variables. 
 *
 * This class is instantiated if the 'storage' option is set as follows:
 * 'storage' => [
 *    'type' => 'pdo',
 *    'dsn' => '< THE DATABASE DSN>'
 * ]
 *
 */
class PdoTokenStorage
	extends AbstractTokenStorage 
	implements TokenStorageInterface, TokenStorageManagementInterface {

	const CREATE_TABLE = [
		'sqlite' => 
			"CREATE TABLE oauth_session (
			id integer NOT NULL primary key autoincrement,
			session char(32) NOT NULL DEFAULT '',
			state char(32) NOT NULL DEFAULT '',
			nonce char(64) NOT NULL DEFAULT '',
			access_token text NOT NULL DEFAULT '',
			expiry datetime DEFAULT NULL,
			type char(12) NOT NULL DEFAULT '',
			provider char(20) NOT NULL DEFAULT '',
			creation datetime NOT NULL DEFAULT '2000-01-01 00:00:00',
			access_token_secret text NOT NULL DEFAULT '',
			authorized char(1) DEFAULT NULL,
			user text DEFAULT NULL,
			refresh_token text NOT NULL DEFAULT '',
			scope text NOT NULL DEFAULT '',
			id_token text NOT NULL DEFAULT '',
			access_token_response text DEFAULT NULL
			);",
		'mysql' => 
			"CREATE TABLE oauth_session (
			id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
			session VARCHAR(32) NOT NULL DEFAULT '',
			state VARCHAR(32) NOT NULL DEFAULT '',
			nonce VARCHAR(64) NOT NULL DEFAULT '',
			access_token TEXT NOT NULL DEFAULT '',
			expiry DATETIME DEFAULT NULL,
			type VARCHAR(12) NOT NULL DEFAULT '',
			provider VARCHAR(20) NOT NULL DEFAULT '',
			creation DATETIME NOT NULL DEFAULT '2000-01-01 00:00:00',
			access_token_secret TEXT NOT NULL DEFAULT '',
			authorized TINYINT(1) DEFAULT NULL,
			user TEXT DEFAULT NULL,
			refresh_token TEXT NOT NULL DEFAULT '',
			scope TEXT NOT NULL DEFAULT '',
			id_token TEXT NOT NULL DEFAULT '',
			access_token_response TEXT DEFAULT NULL
			) ENGINE=INNODB;",
		'pgsql' => 
			"CREATE TABLE oauth_session (
			id serial PRIMARY KEY,
			session VARCHAR(32) NOT NULL DEFAULT '',
			state VARCHAR(32) NOT NULL DEFAULT '',
			nonce VARCHAR(64) NOT NULL DEFAULT '',
			access_token TEXT NOT NULL DEFAULT '',
			expiry datetime DEFAULT NULL,
			type VARCHAR(12) NOT NULL DEFAULT '',
			provider VARCHAR(20) NOT NULL DEFAULT '',
			creation datetime NOT NULL DEFAULT '2000-01-01 00:00:00',
			access_token_secret TEXT NOT NULL DEFAULT '',
			authorized BOOLEAN DEFAULT NULL,
			user TEXT DEFAULT NULL,
			refresh_token TEXT NOT NULL DEFAULT '',
			scope TEXT NOT NULL DEFAULT '',
			id_token TEXT NOT NULL DEFAULT '',
			access_token_response TEXT DEFAULT NULL
			);"
	];

	private $pdo = null;

	/**
	 * {@inheritdoc}
	 */
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

	/**
	 * {@inheritdoc}
	 */
	public function getOAuthSession($sessionId, $provider, &$oauthSession) {
		$parameters = [
			$sessionId, \PDO::PARAM_STR,
			$provider, \PDO::PARAM_STR
		];
		if (!$this->query('SELECT id, session, state, nonce, access_token, access_token_secret, expiry, authorized, type, provider, creation, refresh_token, scope, id_token, access_token_response, user FROM oauth_session WHERE session=? AND provider=?', $parameters, $results)) {
			return false;
		}
		if (count($results) === 0) {
			$oauthSession = null;
			return true;
		}
		$oauthSession = $this->setOAuthSession($results[0]);
		return true;
	}

	/**
	 * {@inheritdoc}
	 */
	public function saveOAuthSession($session) {
		$token = $session->getAccessToken();
		$parameters = [
			$session->getSessionId(), \PDO::PARAM_STR,
			$session->getState(), \PDO::PARAM_STR,
			$session->getNonce(), \PDO::PARAM_STR,
			$token->getValue(), \PDO::PARAM_STR,
			$token->getSecret(), \PDO::PARAM_STR,
			$token->getExpiry(), \PDO::PARAM_STR,
			$token->isAuthorized(), \PDO::PARAM_BOOL,
			$token->getType(), \PDO::PARAM_STR,
			$session->getProvider(), \PDO::PARAM_STR,
			$session->getCreation(), \PDO::PARAM_STR,
			$token->getRefresh(), \PDO::PARAM_STR,
			$token->getScope(), \PDO::PARAM_STR,
			"".$token->getIdToken(), \PDO::PARAM_STR,
			json_encode($token->getResponse()), \PDO::PARAM_STR,
			$session->getUser(), \PDO::PARAM_STR,
			$session->getid(), \PDO::PARAM_INT
		];
		return $this->query('UPDATE oauth_session SET session=?, state=?, nonce=?, access_token=?, access_token_secret=?, expiry=?, authorized=?, type=?, provider=?, creation=?, refresh_token=?, scope=?, id_token=?, access_token_response=?, user=? WHERE id=?', $parameters, $results);
	}

	/**
	 * {@inheritdoc}
	 */
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

	/**
	 * Creates an OAuthSessionValue object from an array of session variables.
	 *
	 * @param array $session the array of session variables
	 *
	 * @return \eureka2\OAuth\Storage\OAuthSessionValue the OAuthSessionValue object to create
	 */
	private function setOAuthSession($session) {
		$accessToken = new AccessToken([
			'value' => $session[4],
			'secret' => $session[5],
			'expiry' => $session[6],
			'authorized' => $session[7],
			'type' => $session[8],
			'refresh' => $session[11],
			'scope' => $session[12],
			'id_token' => $session[13],
			'response' => (isset($session[14]) ? json_decode($session[14]) : null)
		]);
		$oauthSession = new OAuthSessionValue();
		$oauthSession->setId($session[0]);
		$oauthSession->setSession($session[1]);
		$oauthSession->setState($session[2]);
		$oauthSession->setNonce($session[3]);
		$oauthSession->setAccessToken($accessToken);
		$oauthSession->setProvider($session[9]);
		$oauthSession->setCreation($session[10]);
		$oauthSession->setUser($session[15]);
		return $oauthSession;
	}

	/**
	 * Checks if the OAuth session table exists
	 *
	 * @return bool true if the OAuth session table exists, false otherwise
	 */
	private function tableExists() {
		try {
			$result = $this->pdo->query("SELECT 1 FROM oauth_session LIMIT 1");
		} catch (\Exception $e) {
			return false;
		}
		return $result !== false;
	}

	/**
	 * Creates the OAuth session table
	 *
	 * @throws OAuthClientException if an error occurs.
	 */
	private function createTable() {
		try {
			$driver = $this->pdo->getAttribute(\PDO::ATTR_DRIVER_NAME);
			if (!isset(self::CREATE_TABLE[$driver])) {
			throw new OAuthClientException(
				sprintf(
					'The database driver %s is not supported',
					$driver
				)
			);
			}
			$this->pdo->setAttribute( \PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION );
			$sql = self::CREATE_TABLE[$driver];
			$this->pdo->exec($sql);
		} catch(\Exception $e) {
			throw new OAuthClientException(
				sprintf(
					'Unable to create the token storage table : %s',
					$e->getMessage()
				)
			);
		}
		try {
			 $sql = "CREATE UNIQUE INDEX oauth_session_index ON oauth_session(session, provider)";
			 $this->pdo->exec($sql);
		} catch(\Exception $e) {
			throw new OAuthClientException(
				sprintf(
					'Unable to create the token storage table index : %s',
					$e->getMessage()
				)
			);
		}
	}

	/**
	 * Connects to the database
	 *
	 * @throws OAuthClientException if an error occurs.
	 */
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
		if (!$this->tableExists()) {
			$this->createTable();
		}
	}

	/**
	 * Executes a query on the session table
	 *
	 * @return bool true if the query succeeds, false otherwise
	 */
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
