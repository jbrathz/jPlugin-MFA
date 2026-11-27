<?php
/**
 * Encryption for secrets at rest.
 *
 * Keys are derived from the site salts (or an optional JMFA_KEY constant),
 * never stored next to the ciphertext.
 *
 * @package jPlugin-MFA
 */

if (!defined('ABSPATH')) {
	exit;
}

class JMFA_Crypto {

	const SODIUM_PREFIX  = 's1:';
	const OPENSSL_PREFIX = 'g1:';

	/**
	 * @var string|null
	 */
	private static $key = null;

	/**
	 * 32 raw bytes derived from the site salts.
	 *
	 * Rotating AUTH_KEY/AUTH_SALT makes stored secrets unreadable, which the
	 * plugin treats as "must enrol again" rather than as a fatal error.
	 *
	 * @return string
	 */
	public static function key() {
		if (self::$key !== null) {
			return self::$key;
		}

		if (defined('JMFA_KEY') && is_string(JMFA_KEY) && JMFA_KEY !== '') {
			self::$key = hash('sha256', 'jmfa-key|' . JMFA_KEY, true);
			return self::$key;
		}

		$auth = defined('AUTH_KEY') ? (string) AUTH_KEY : '';
		$salt = defined('AUTH_SALT') ? (string) AUTH_SALT : '';

		self::$key = hash('sha256', 'jmfa-v1|' . $auth . '|' . $salt, true);

		return self::$key;
	}

	/**
	 * @param string $plaintext Value to protect.
	 * @return string|false Ciphertext envelope, false when no cipher is available.
	 */
	public static function encrypt($plaintext) {
		$plaintext = (string) $plaintext;

		if ($plaintext === '') {
			return false;
		}

		$key = self::key();

		if (function_exists('sodium_crypto_secretbox') && defined('SODIUM_CRYPTO_SECRETBOX_NONCEBYTES')) {
			try {
				$nonce  = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
				$cipher = sodium_crypto_secretbox($plaintext, $nonce, $key);

				return self::SODIUM_PREFIX . base64_encode($nonce . $cipher);
			} catch (Exception $e) {
				return false;
			}
		}

		if (function_exists('openssl_encrypt') && in_array('aes-256-gcm', openssl_get_cipher_methods(), true)) {
			$iv     = random_bytes(12);
			$tag    = '';
			$cipher = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);

			if (false === $cipher) {
				return false;
			}

			return self::OPENSSL_PREFIX . base64_encode($iv . $tag . $cipher);
		}

		return false;
	}

	/**
	 * @param string $payload Stored envelope.
	 * @return string|false Plaintext, false when unreadable (e.g. salts rotated).
	 */
	public static function decrypt($payload) {
		$payload = (string) $payload;

		if ($payload === '') {
			return false;
		}

		$key = self::key();

		if (0 === strpos($payload, self::SODIUM_PREFIX)) {
			if (!function_exists('sodium_crypto_secretbox_open') || !defined('SODIUM_CRYPTO_SECRETBOX_NONCEBYTES')) {
				return false;
			}

			$raw = base64_decode(substr($payload, strlen(self::SODIUM_PREFIX)), true);

			if (false === $raw || strlen($raw) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
				return false;
			}

			$nonce  = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
			$cipher = substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

			try {
				$plain = sodium_crypto_secretbox_open($cipher, $nonce, $key);
			} catch (Exception $e) {
				return false;
			}

			return is_string($plain) ? $plain : false;
		}

		if (0 === strpos($payload, self::OPENSSL_PREFIX)) {
			if (!function_exists('openssl_decrypt')) {
				return false;
			}

			$raw = base64_decode(substr($payload, strlen(self::OPENSSL_PREFIX)), true);

			if (false === $raw || strlen($raw) <= 28) {
				return false;
			}

			$iv     = substr($raw, 0, 12);
			$tag    = substr($raw, 12, 16);
			$cipher = substr($raw, 28);

			$plain = openssl_decrypt($cipher, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);

			return is_string($plain) ? $plain : false;
		}

		return false;
	}

	/**
	 * Keyed digest for values that must be looked up (recovery codes).
	 *
	 * @param string $value Normalised value.
	 * @return string 64 hex characters.
	 */
	public static function hmac($value) {
		return hash_hmac('sha256', (string) $value, self::key());
	}
}