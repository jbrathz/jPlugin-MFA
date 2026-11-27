<?php
/**
 * TOTP (RFC 6238) and Base32 (RFC 4648).
 *
 * Fixed profile so every standard authenticator app works:
 * SHA-1, 6 digits, 30 second period. No proprietary extension.
 *
 * @package jPlugin-MFA
 */

if (!defined('ABSPATH')) {
	exit;
}

class JMFA_TOTP {

	const DIGITS       = 6;
	const PERIOD       = 30;
	const SECRET_BYTES = 20;
	const ALPHABET     = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * New random secret, Base32 encoded without padding.
	 *
	 * @return string
	 */
	public static function generate_secret() {
		try {
			$raw = random_bytes(self::SECRET_BYTES);
		} catch (Exception $e) {
			$raw = '';
			for ($i = 0; $i < self::SECRET_BYTES; $i++) {
				$raw .= chr(wp_rand(0, 255));
			}
		}

		return self::base32_encode($raw);
	}

	/**
	 * @param string $data Raw bytes.
	 * @return string
	 */
	public static function base32_encode($data) {
		$bits = '';

		$length = strlen($data);
		for ($i = 0; $i < $length; $i++) {
			$bits .= str_pad(decbin(ord($data[ $i ])), 8, '0', STR_PAD_LEFT);
		}

		$output = '';
		foreach (str_split($bits, 5) as $chunk) {
			$output .= self::ALPHABET[ bindec(str_pad($chunk, 5, '0', STR_PAD_RIGHT)) ];
		}

		return $output;
	}

	/**
	 * @param string $secret Base32 secret, padding and separators are ignored.
	 * @return string|false Raw bytes, false when the secret is invalid.
	 */
	public static function base32_decode($secret) {
		$secret = strtoupper(preg_replace('/[^A-Za-z2-7]/', '', (string) $secret));

		if ($secret === '') {
			return false;
		}

		$bits   = '';
		$length = strlen($secret);

		for ($i = 0; $i < $length; $i++) {
			$position = strpos(self::ALPHABET, $secret[ $i ]);

			if (false === $position) {
				return false;
			}

			$bits .= str_pad(decbin($position), 5, '0', STR_PAD_LEFT);
		}

		$output = '';
		foreach (str_split($bits, 8) as $byte) {
			if (8 === strlen($byte)) {
				$output .= chr(bindec($byte));
			}
		}

		return $output;
	}

	/**
	 * Time step for a timestamp.
	 *
	 * @param int|null $timestamp Unix time, defaults to now.
	 * @return int
	 */
	public static function time_step($timestamp = null) {
		$timestamp = (null === $timestamp) ? time() : (int) $timestamp;

		return (int) floor($timestamp / self::PERIOD);
	}

	/**
	 * HOTP value for one counter (RFC 4226).
	 *
	 * @param string $secret Base32 secret.
	 * @param int    $counter Counter / time step.
	 * @return string|false Zero padded code.
	 */
	public static function hotp($secret, $counter) {
		$key = self::base32_decode($secret);

		if (false === $key || '' === $key) {
			return false;
		}

		$counter = max(0, (int) $counter);
		$message = pack('N2', 0, $counter); // 64 bit big endian, high word unused.
		$hash    = hash_hmac('sha1', $message, $key, true);

		if (false === $hash || strlen($hash) < 20) {
			return false;
		}

		$offset = ord(substr($hash, -1)) & 0x0f;
		$part   = unpack('N', substr($hash, $offset, 4));

		if (!is_array($part) || !isset($part[1])) {
			return false;
		}

		$value = $part[1] & 0x7fffffff;

		return str_pad((string) ($value % (int) pow(10, self::DIGITS)), self::DIGITS, '0', STR_PAD_LEFT);
	}

	/**
	 * Verify a code and return the accepted time step.
	 *
	 * Rejects any step at or below $last_step, which also blocks replay of the
	 * same code inside its 30 second window.
	 *
	 * @param string   $secret    Base32 secret.
	 * @param string   $code      User supplied code, separators allowed.
	 * @param int      $window    Allowed drift in steps (0-5).
	 * @param int      $last_step Highest step already used, 0 when none.
	 * @param int|null $timestamp Unix time, defaults to now.
	 * @return int|false Accepted time step, false on failure.
	 */
	public static function verify($secret, $code, $window = 1, $last_step = 0, $timestamp = null) {
		$code = preg_replace('/\D/', '', (string) $code);

		if (strlen($code) !== self::DIGITS) {
			return false;
		}

		$current  = self::time_step($timestamp);
		$window   = max(0, min(5, (int) $window));
		$last_step = (int) $last_step;
		$accepted = false;

		for ($offset = -$window; $offset <= $window; $offset++) {
			$step = $current + $offset;

			if ($step <= 0) {
				continue;
			}

			if ($last_step > 0 && $step <= $last_step) {
				continue;
			}

			$expected = self::hotp($secret, $step);

			if (false !== $expected && hash_equals($expected, $code)) {
				if (false === $accepted || $step > $accepted) {
					$accepted = $step;
				}
			}
		}

		return $accepted;
	}

	/**
	 * otpauth:// URI understood by Google Authenticator and every other app.
	 *
	 * @param string $secret  Base32 secret.
	 * @param string $account Account label (user login).
	 * @param string $issuer  Issuer label (site name).
	 * @return string
	 */
	public static function provisioning_uri($secret, $account, $issuer) {
		$label = $issuer . ':' . $account;

		$query = http_build_query(
			array(
				'secret'    => $secret,
				'issuer'    => $issuer,
				'algorithm' => 'SHA1',
				'digits'    => self::DIGITS,
				'period'    => self::PERIOD,
			),
			'',
			'&',
			PHP_QUERY_RFC3986
		);

		return 'otpauth://totp/' . rawurlencode($label) . '?' . $query;
	}

	/**
	 * Group a secret in blocks of four for manual entry.
	 *
	 * @param string $secret Base32 secret.
	 * @return string
	 */
	public static function format_secret($secret) {
		return trim(chunk_split((string) $secret, 4, ' '));
	}
}