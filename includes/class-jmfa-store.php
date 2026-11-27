<?php
/**
 * User state and pending-login storage.
 *
 * @package jPlugin-MFA
 */

if (!defined('ABSPATH')) {
	exit;
}

class JMFA_Store {

	const META_STATUS        = '_jmfa_status';
	const META_SECRET        = '_jmfa_secret';
	const META_LAST_STEP     = '_jmfa_last_step';
	const META_RECOVERY      = '_jmfa_recovery';
	const META_ENROLLED_AT   = '_jmfa_enrolled_at';
	const META_SETUP         = '_jmfa_setup';
	const META_SETUP_EXPIRES = '_jmfa_setup_expires';

	const PENDING_TTL      = 600;
	const RECOVERY_COUNT   = 10;
	const RECOVERY_LENGTH  = 10;
	const RECOVERY_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // Crockford base32, no I L O U.

	/* ---------------------------------------------------------------------
	 * Per user state
	 * ------------------------------------------------------------------ */

	/**
	 * @param int $user_id User ID.
	 * @return string '', 'enabled' or 'disabled'.
	 */
	public static function status($user_id) {
		return (string) get_user_meta((int) $user_id, self::META_STATUS, true);
	}

	/**
	 * @param int $user_id User ID.
	 * @return bool
	 */
	public static function is_enabled($user_id) {
		return 'enabled' === self::status($user_id);
	}

	/**
	 * @param int $user_id User ID.
	 * @return string|false Decrypted Base32 secret.
	 */
	public static function secret($user_id) {
		$stored = (string) get_user_meta((int) $user_id, self::META_SECRET, true);

		if ('' === $stored) {
			return false;
		}

		$plain = JMFA_Crypto::decrypt($stored);

		return (is_string($plain) && '' !== $plain) ? $plain : false;
	}

	/**
	 * @param int $user_id User ID.
	 * @return int
	 */
	public static function last_step($user_id) {
		return (int) get_user_meta((int) $user_id, self::META_LAST_STEP, true);
	}

	/**
	 * @param int $user_id User ID.
	 * @param int $step    Accepted time step.
	 */
	public static function set_last_step($user_id, $step) {
		update_user_meta((int) $user_id, self::META_LAST_STEP, (int) $step);
	}

	/**
	 * Turn MFA on for a user.
	 *
	 * @param int    $user_id      User ID.
	 * @param string $plain_secret Base32 secret in clear text.
	 * @param int    $step         Time step used to confirm.
	 * @param array  $codes        Plain recovery codes, stored hashed.
	 * @return bool
	 */
	public static function enable($user_id, $plain_secret, $step, array $codes) {
		$user_id = (int) $user_id;
		$sealed  = JMFA_Crypto::encrypt($plain_secret);

		if (false === $sealed) {
			return false;
		}

		update_user_meta($user_id, self::META_SECRET, $sealed);
		update_user_meta($user_id, self::META_STATUS, 'enabled');
		update_user_meta($user_id, self::META_LAST_STEP, (int) $step);
		update_user_meta($user_id, self::META_ENROLLED_AT, time());

		self::store_recovery_codes($user_id, $codes);
		self::forget_setup($user_id);

		return true;
	}

	/**
	 * @param int $user_id User ID.
	 */
	public static function disable($user_id) {
		$user_id = (int) $user_id;

		delete_user_meta($user_id, self::META_SECRET);
		delete_user_meta($user_id, self::META_LAST_STEP);
		delete_user_meta($user_id, self::META_RECOVERY);
		delete_user_meta($user_id, self::META_ENROLLED_AT);
		self::forget_setup($user_id);

		update_user_meta($user_id, self::META_STATUS, 'disabled');
		self::delete_pending_for_user($user_id);
	}

	/**
	 * @param int $user_id User ID.
	 */
	public static function forget_setup($user_id) {
		delete_user_meta((int) $user_id, self::META_SETUP);
		delete_user_meta((int) $user_id, self::META_SETUP_EXPIRES);
	}

	/* ---------------------------------------------------------------------
	 * Recovery codes
	 * ------------------------------------------------------------------ */

	/**
	 * @return array Plain codes, formatted xxxxx-xxxxx.
	 */
	public static function generate_recovery_codes() {
		$codes    = array();
		$alphabet = self::RECOVERY_ALPHABET;
		$max      = strlen($alphabet) - 1;

		for ($i = 0; $i < self::RECOVERY_COUNT; $i++) {
			$code = '';

			for ($j = 0; $j < self::RECOVERY_LENGTH; $j++) {
				$code .= $alphabet[ random_int(0, $max) ];
			}

			$codes[] = substr($code, 0, 5) . '-' . substr($code, 5);
		}

		return $codes;
	}

	/**
	 * Strip formatting and map ambiguous characters.
	 *
	 * @param string $code User input.
	 * @return string
	 */
	public static function normalize_recovery_code($code) {
		$code = strtoupper(preg_replace('/[^A-Za-z0-9]/', '', (string) $code));
		$code = str_replace(array('I', 'L'), '1', $code);

		return str_replace('O', '0', $code);
	}

	/**
	 * @param int   $user_id User ID.
	 * @param array $codes   Plain codes.
	 */
	public static function store_recovery_codes($user_id, array $codes) {
		$hashes = array();

		foreach ($codes as $code) {
			$normalized = self::normalize_recovery_code($code);

			if ('' !== $normalized) {
				$hashes[] = JMFA_Crypto::hmac('recovery|' . $normalized);
			}
		}

		update_user_meta((int) $user_id, self::META_RECOVERY, $hashes);
	}

	/**
	 * @param int $user_id User ID.
	 * @return int
	 */
	public static function recovery_remaining($user_id) {
		$hashes = get_user_meta((int) $user_id, self::META_RECOVERY, true);

		return is_array($hashes) ? count($hashes) : 0;
	}

	/**
	 * Consume a recovery code, single use.
	 *
	 * @param int    $user_id User ID.
	 * @param string $code    User input.
	 * @return bool
	 */
	public static function consume_recovery_code($user_id, $code) {
		$user_id    = (int) $user_id;
		$normalized = self::normalize_recovery_code($code);

		if ('' === $normalized) {
			return false;
		}

		$hashes = get_user_meta($user_id, self::META_RECOVERY, true);

		if (!is_array($hashes) || !$hashes) {
			return false;
		}

		$needle    = JMFA_Crypto::hmac('recovery|' . $normalized);
		$remaining = array();
		$matched   = false;

		foreach ($hashes as $hash) {
			if (!$matched && is_string($hash) && hash_equals($hash, $needle)) {
				$matched = true;
				continue;
			}

			$remaining[] = $hash;
		}

		if (!$matched) {
			return false;
		}

		update_user_meta($user_id, self::META_RECOVERY, $remaining);

		return true;
	}

	/* ---------------------------------------------------------------------
	 * Pending logins
	 * ------------------------------------------------------------------ */

	/**
	 * @param int    $user_id     User ID.
	 * @param string $stage       verify|enroll|codes.
	 * @param bool   $remember    Remember me flag.
	 * @param string $redirect_to Validated redirect target.
	 * @return array|false array('id' => int, 'token' => string)
	 */
	public static function create_pending($user_id, $stage, $remember, $redirect_to) {
		global $wpdb;

		if (!JMFA_DB::table_exists(JMFA_DB::PENDING)) {
			return false;
		}

		try {
			$token = bin2hex(random_bytes(32));
		} catch (Exception $e) {
			return false;
		}

		$now  = time();
		$data = array(
			'token_hash'  => hash('sha256', $token),
			'user_id'     => (int) $user_id,
			'stage'       => in_array($stage, array('verify', 'enroll', 'codes'), true) ? $stage : 'verify',
			'remember'    => $remember ? 1 : 0,
			'redirect_to' => substr((string) $redirect_to, 0, 255),
			'ip_hash'     => JMFA_Audit::ip_hash(),
			'ua_hash'     => JMFA_Audit::ua_hash(),
			'attempts'    => 0,
			'created_at'  => gmdate('Y-m-d H:i:s', $now),
			'expires_at'  => gmdate('Y-m-d H:i:s', $now + self::PENDING_TTL),
		);

		$inserted = $wpdb->insert(
			JMFA_DB::table(JMFA_DB::PENDING),
			$data,
			array('%s', '%d', '%s', '%d', '%s', '%s', '%s', '%d', '%s', '%s')
		);

		if (!$inserted) {
			return false;
		}

		return array(
			'id'    => (int) $wpdb->insert_id,
			'token' => $token,
		);
	}

	/**
	 * @param string $token Raw cookie token.
	 * @return object|null
	 */
	public static function get_pending($token) {
		global $wpdb;

		$token = (string) $token;

		if ('' === $token || !JMFA_DB::table_exists(JMFA_DB::PENDING)) {
			return null;
		}

		$table = JMFA_DB::table(JMFA_DB::PENDING);
		$row   = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE token_hash = %s AND expires_at > %s LIMIT 1",
				hash('sha256', $token),
				gmdate('Y-m-d H:i:s')
			)
		);

		return $row ? $row : null;
	}

	/**
	 * @param int $id Pending row ID.
	 * @return object|null
	 */
	public static function get_pending_by_id($id) {
		global $wpdb;

		if (!JMFA_DB::table_exists(JMFA_DB::PENDING)) {
			return null;
		}

		$table = JMFA_DB::table(JMFA_DB::PENDING);
		$row   = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$table} WHERE id = %d", (int) $id));

		return $row ? $row : null;
	}

	/**
	 * @param int $id  Pending row ID.
	 * @param int $ttl New lifetime in seconds.
	 */
	public static function touch_pending($id, $ttl = self::PENDING_TTL) {
		global $wpdb;

		$wpdb->update(
			JMFA_DB::table(JMFA_DB::PENDING),
			array('expires_at' => gmdate('Y-m-d H:i:s', time() + max(60, (int) $ttl))),
			array('id' => (int) $id),
			array('%s'),
			array('%d')
		);
	}

	/**
	 * @param int    $id    Pending row ID.
	 * @param string $stage verify|enroll|codes.
	 */
	public static function set_stage($id, $stage) {
		global $wpdb;

		if (!in_array($stage, array('verify', 'enroll', 'codes'), true)) {
			return;
		}

		$wpdb->update(
			JMFA_DB::table(JMFA_DB::PENDING),
			array('stage' => $stage),
			array('id' => (int) $id),
			array('%s'),
			array('%d')
		);
	}

	/**
	 * @param int $id Pending row ID.
	 * @return int Attempts after increment.
	 */
	public static function bump_attempts($id) {
		global $wpdb;

		$table = JMFA_DB::table(JMFA_DB::PENDING);

		$wpdb->query($wpdb->prepare("UPDATE {$table} SET attempts = attempts + 1 WHERE id = %d", (int) $id));

		return (int) $wpdb->get_var($wpdb->prepare("SELECT attempts FROM {$table} WHERE id = %d", (int) $id));
	}

	/**
	 * @param int $id Pending row ID.
	 */
	public static function delete_pending($id) {
		global $wpdb;

		$wpdb->delete(JMFA_DB::table(JMFA_DB::PENDING), array('id' => (int) $id), array('%d'));
	}

	/**
	 * @param string $token Raw token.
	 */
	public static function delete_pending_by_token($token) {
		global $wpdb;

		$token = (string) $token;

		if ('' === $token) {
			return;
		}

		$wpdb->delete(
			JMFA_DB::table(JMFA_DB::PENDING),
			array('token_hash' => hash('sha256', $token)),
			array('%s')
		);
	}

	/**
	 * @param int $user_id User ID.
	 */
	public static function delete_pending_for_user($user_id) {
		global $wpdb;

		$wpdb->delete(JMFA_DB::table(JMFA_DB::PENDING), array('user_id' => (int) $user_id), array('%d'));
	}

	/**
	 * Remove every pending login. Used on deactivation so no half finished
	 * authentication survives a disable/enable cycle.
	 */
	public static function purge_pending() {
		global $wpdb;

		if (!JMFA_DB::table_exists(JMFA_DB::PENDING)) {
			return;
		}

		$table = JMFA_DB::table(JMFA_DB::PENDING);

		$wpdb->query("DELETE FROM {$table}");
	}

	/**
	 * Daily maintenance: expired pending logins and old audit rows.
	 *
	 * Runs from cron and from the safety net in JMFA_Plugin, so retention is
	 * enforced even when WP-Cron is disabled or the site gets no traffic.
	 */
	public static function prune() {
		global $wpdb;

		if (JMFA_DB::table_exists(JMFA_DB::PENDING)) {
			$table = JMFA_DB::table(JMFA_DB::PENDING);

			$wpdb->query($wpdb->prepare("DELETE FROM {$table} WHERE expires_at < %s", gmdate('Y-m-d H:i:s')));
		}

		JMFA_Audit::prune((int) JMFA_Policy::get('log_retention', 90));

		update_option('jmfa_last_prune', time(), false);
	}

	/**
	 * Temporary recovery codes shown right after activation in a new pending
	 * session. Encrypted, short lived, deleted as soon as they are finished.
	 *
	 * @param int   $pending_id Pending row ID.
	 * @param array $codes      Plain codes.
	 */
	public static function stash_codes($pending_id, array $codes) {
		$sealed = JMFA_Crypto::encrypt(wp_json_encode(array_values($codes)) );

		if (false !== $sealed) {
			set_transient('jmfa_codes_' . (int) $pending_id, $sealed, 15 * MINUTE_IN_SECONDS);
		}
	}

	/**
	 * @param int $pending_id Pending row ID.
	 * @return array Plain codes, empty when they were already shown.
	 */
	public static function take_codes($pending_id) {
		$key    = 'jmfa_codes_' . (int) $pending_id;
		$sealed = get_transient($key);

		if (!$sealed) {
			return array();
		}

		$plain = JMFA_Crypto::decrypt($sealed);

		if (!is_string($plain)) {
			return array();
		}

		$codes = json_decode($plain, true);

		return is_array($codes) ? $codes : array();
	}

	/**
	 * @param int $pending_id Pending row ID.
	 */
	public static function forget_codes($pending_id) {
		delete_transient('jmfa_codes_' . (int) $pending_id);
	}
}