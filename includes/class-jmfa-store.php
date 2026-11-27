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
	 * @return string '', 'enabled', 'disabled' or 'unavailable'.
	 */
	public static function status($user_id) {
		$credential = self::credential($user_id);

		return $credential ? $credential->state : 'unavailable';
	}

	/**
	 * @param int $user_id User ID.
	 * @return bool
	 */
	public static function is_enabled($user_id) {
		return 'enabled' === self::status($user_id);
	}

	/**
	 * Return the current credential or read the original user meta. Persist the
	 * original data on first use, without overwriting a concurrent migration.
	 *
	 * @param int  $user_id User ID.
	 * @param bool $persist Create an authoritative row if needed.
	 * @return object|false
	 */
	public static function credential($user_id, $persist = false) {
		global $wpdb;

		$user_id = (int) $user_id;
		$table   = JMFA_DB::table(JMFA_DB::CREDENTIALS);
		$select  = $wpdb->prepare("SELECT * FROM {$table} WHERE user_id = %d", $user_id);
		$row     = $wpdb->get_row($select);

		if ('' !== $wpdb->last_error) {
			return false;
		}

		if ($row) {
			return $row;
		}

		$state  = (string) get_user_meta($user_id, self::META_STATUS, true);
		$hashes = get_user_meta($user_id, self::META_RECOVERY, true);
		$legacy = array(
			'user_id'    => $user_id,
			'state'      => in_array($state, array('enabled', 'disabled'), true) ? $state : '',
			'generation' => '',
			'secret'     => (string) get_user_meta($user_id, self::META_SECRET, true),
			'last_step'  => max(0, (int) get_user_meta($user_id, self::META_LAST_STEP, true)),
			'recovery'   => wp_json_encode(is_array($hashes) ? array_values($hashes) : array()),
		);

		if (!$persist) {
			return (object) $legacy;
		}

		$legacy['generation'] = bin2hex(random_bytes(16));

		if (false === $wpdb->query($wpdb->prepare(
			"INSERT INTO {$table} (user_id, state, generation, secret, last_step, recovery)
			VALUES (%d, %s, %s, %s, %d, %s) ON DUPLICATE KEY UPDATE user_id = user_id",
			array_values($legacy)
		))) {
			return false;
		}

		return $wpdb->get_row($select) ?: false;
	}

	/**
	 * List enrolled users on this site, including users not yet migrated.
	 *
	 * @return int[]
	 */
	public static function enabled_user_ids() {
		global $wpdb;

		$table = JMFA_DB::table(JMFA_DB::CREDENTIALS);
		$ids   = $wpdb->get_col("SELECT user_id FROM {$table} WHERE state = 'enabled'");
		$old   = get_users(array(
			'fields'     => 'ID',
			'meta_key'   => self::META_STATUS,
			'meta_value' => 'enabled',
		));

		foreach ($old as $id) {
			if (self::is_enabled($id)) {
				$ids[] = $id;
			}
		}

		if (!$ids) {
			return array();
		}

		return get_users(array('fields' => 'ID', 'include' => array_unique(array_map('intval', $ids))));
	}

	/**
	 * Publish the complete credential only for the still-current, unused setup.
	 */
	public static function enable($user_id, $generation, $plain_secret, $step, array $codes, $pending = null) {
		global $wpdb;

		$sealed = JMFA_Crypto::encrypt($plain_secret);
		$hashes = self::hash_recovery_codes($codes);

		if (false === $sealed || false === $hashes) {
			return false;
		}

		$table = JMFA_DB::table(JMFA_DB::CREDENTIALS);

		if ($pending) {
			$challenges = JMFA_DB::table(JMFA_DB::PENDING);
			$now = time();

			return 2 === $wpdb->query($wpdb->prepare(
				"UPDATE {$table} AS c INNER JOIN {$challenges} AS p ON p.user_id = c.user_id
				SET c.state = 'enabled', c.secret = %s, c.last_step = %d, c.recovery = %s,
					p.stage = 'codes', p.setup_secret = NULL, p.expires_at = %s
				WHERE c.user_id = %d AND c.generation = %s AND c.state <> 'enabled'
					AND p.id = %d AND p.generation = c.generation AND p.stage = 'enroll' AND p.expires_at > %s",
				$sealed, (int) $step, $hashes, gmdate('Y-m-d H:i:s', $now + self::PENDING_TTL),
				(int) $user_id, $generation, (int) $pending->id, gmdate('Y-m-d H:i:s', $now)
			));
		}

		return 1 === $wpdb->query($wpdb->prepare(
			"UPDATE {$table} SET state = 'enabled', secret = %s, last_step = %d, recovery = %s
			WHERE user_id = %d AND generation = %s AND state <> 'enabled'",
			$sealed, (int) $step, $hashes, (int) $user_id, $generation
		));
	}

	/**
	 * @param int $user_id User ID.
	 * @param string|null $generation Require this credential when disabling from self-service.
	 * @return bool
	 */
	public static function disable($user_id, $generation = null) {
		global $wpdb;

		$user_id = (int) $user_id;
		$row     = self::credential($user_id, true);

		if (!$row) {
			return false;
		}

		$table = JMFA_DB::table(JMFA_DB::CREDENTIALS);
		$changed = $wpdb->query($wpdb->prepare(
			"UPDATE {$table} SET state = 'disabled', generation = %s, secret = '', last_step = 0, recovery = '[]'
			WHERE user_id = %d AND generation = %s",
			bin2hex(random_bytes(16)), $user_id, $generation ?? $row->generation
		));

		if (1 !== $changed) {
			return false;
		}

		self::forget_legacy_credential($user_id);

		return true;
	}

	private static function forget_legacy_credential($user_id) {
		foreach (array(self::META_SECRET, self::META_LAST_STEP, self::META_RECOVERY, self::META_ENROLLED_AT,
			self::META_SETUP, self::META_SETUP_EXPIRES, self::META_STATUS) as $key) {
			delete_user_meta((int) $user_id, $key);
		}
	}

	public static function delete_user($user_id) {
		global $wpdb;

		$wpdb->delete(JMFA_DB::table(JMFA_DB::CREDENTIALS), array('user_id' => (int) $user_id), array('%d'));
		self::delete_pending_for_user($user_id);
	}

	/**
	 * Accept only a strictly newer step of the same credential generation.
	 */
	public static function consume_totp($user_id, $code, $generation) {
		global $wpdb;

		$row = self::credential($user_id, true);
		if (!$row || 'enabled' !== $row->state || $row->generation !== $generation) {
			return false;
		}

		$secret = JMFA_Crypto::decrypt($row->secret);
		$step = false === $secret ? false : JMFA_TOTP::verify(
			$secret, $code, (int) JMFA_Policy::get('window', 1), (int) $row->last_step
		);

		if (false === $step) {
			return false;
		}

		$table = JMFA_DB::table(JMFA_DB::CREDENTIALS);

		return 1 === $wpdb->query($wpdb->prepare(
			"UPDATE {$table} SET last_step = %d
			WHERE user_id = %d AND state = 'enabled' AND generation = %s AND last_step < %d",
			$step, (int) $user_id, $generation, $step
		));
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
	 * @param array $codes   Plain codes.
	 * @return string|false JSON list of keyed hashes.
	 */
	private static function hash_recovery_codes(array $codes) {
		$hashes = array();

		foreach ($codes as $code) {
			$normalized = self::normalize_recovery_code($code);

			if ('' !== $normalized) {
				$hashes[] = JMFA_Crypto::hmac('recovery|' . $normalized);
			}
		}

		return wp_json_encode(array_values(array_unique($hashes)));
	}

	public static function store_recovery_codes($user_id, array $codes, $generation) {
		global $wpdb;

		$hashes = self::hash_recovery_codes($codes);
		$table  = JMFA_DB::table(JMFA_DB::CREDENTIALS);

		return false !== $hashes && 1 === $wpdb->query($wpdb->prepare(
			"UPDATE {$table} SET recovery = %s WHERE user_id = %d AND state = 'enabled' AND generation = %s",
			$hashes, (int) $user_id, $generation
		));
	}

	/**
	 * @param int $user_id User ID.
	 * @return int
	 */
	public static function recovery_remaining($user_id) {
		$row    = self::credential($user_id);
		$hashes = $row && 'enabled' === $row->state ? json_decode($row->recovery, true) : array();

		return is_array($hashes) ? count($hashes) : 0;
	}

	/**
	 * Consume a recovery code, single use.
	 *
	 * @param int    $user_id User ID.
	 * @param string $code    User input.
	 * @param string $generation Current credential generation.
	 * @return bool
	 */
	public static function consume_recovery_code($user_id, $code, $generation) {
		global $wpdb;

		$user_id    = (int) $user_id;
		$normalized = self::normalize_recovery_code($code);

		if (self::RECOVERY_LENGTH !== strlen($normalized)) {
			return false;
		}

		$row = self::credential($user_id, true);
		if (!$row || 'enabled' !== $row->state || $row->generation !== $generation) {
			return false;
		}

		$hashes = json_decode($row->recovery, true);

		if (!is_array($hashes) || !$hashes) {
			return false;
		}

		$needle    = JMFA_Crypto::hmac('recovery|' . $normalized);
		$remaining = array();
		$matched   = false;

		foreach ($hashes as $hash) {
			if (is_string($hash) && hash_equals($hash, $needle)) {
				$matched = true;
				continue;
			}

			$remaining[] = $hash;
		}

		if (!$matched) {
			return false;
		}

		$table = JMFA_DB::table(JMFA_DB::CREDENTIALS);

		return 1 === $wpdb->query($wpdb->prepare(
			"UPDATE {$table} SET recovery = %s
			WHERE user_id = %d AND state = 'enabled' AND generation = %s AND BINARY recovery = %s",
			wp_json_encode($remaining), $user_id, $generation, $row->recovery
		));
	}

	/* ---------------------------------------------------------------------
	 * Pending logins
	 * ------------------------------------------------------------------ */

	/**
	 * @param int    $user_id     User ID.
	 * @param object $credential  Credential with a persisted generation identifier.
	 * @param bool   $remember    Remember me flag.
	 * @param string $redirect_to Validated redirect target.
	 * @param array  $context     Native login state used on completion.
	 * @return array|false array('id' => int, 'token' => string)
	 */
	public static function create_pending($user_id, $credential, $remember, $redirect_to, array $context) {
		global $wpdb;

		if (JMFA_DB_VERSION !== get_option(JMFA_DB::VERSION_OPTION)) {
			return false;
		}

		try {
			$token = bin2hex(random_bytes(32));
			$stage = 'enabled' === $credential->state ? 'verify' : 'enroll';
			$setup = 'enroll' === $stage ? JMFA_Crypto::encrypt(JMFA_TOTP::generate_secret()) : null;
		} catch (Exception $e) {
			return false;
		}

		if (false === $setup) {
			return false;
		}

		$now  = time();
		$data = array(
			'token_hash'  => hash('sha256', $token),
			'user_id'     => (int) $user_id,
			'stage'       => $stage,
			'remember'    => $remember ? 1 : 0,
			'redirect_to' => $redirect_to,
			'generation'  => $credential->generation,
			'setup_secret' => $setup,
			'login_context' => wp_json_encode($context),
			'ip_hash'     => JMFA_Audit::ip_hash(),
			'ua_hash'     => JMFA_Audit::ua_hash(),
			'attempts'    => 0,
			'created_at'  => gmdate('Y-m-d H:i:s', $now),
			'expires_at'  => gmdate('Y-m-d H:i:s', $now + self::PENDING_TTL),
		);

		$inserted = $wpdb->insert(
			JMFA_DB::table(JMFA_DB::PENDING),
			$data,
			array('%s', '%d', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s')
		);

		if (!$inserted) {
			return false;
		}

		return array(
			'id'    => (int) $wpdb->insert_id,
			'token' => $token,
			'stage' => $stage,
		);
	}

	/**
	 * @param string $token Raw cookie token.
	 * @return object|null
	 */
	public static function get_pending($token) {
		global $wpdb;

		$token = (string) $token;

		if (!preg_match('/\A[a-f0-9]{64}\z/', $token)) {
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

		$table = JMFA_DB::table(JMFA_DB::PENDING);
		return $wpdb->get_row($wpdb->prepare(
			"SELECT * FROM {$table} WHERE id = %d AND expires_at > %s",
			(int) $id, gmdate('Y-m-d H:i:s')
		));
	}

	/**
	 * Reserve one attempt before evaluating a code, including concurrent requests.
	 */
	public static function reserve_attempt($pending, $limit) {
		global $wpdb;

		$table = JMFA_DB::table(JMFA_DB::PENDING);

		return 1 === $wpdb->query($wpdb->prepare(
			"UPDATE {$table} SET attempts = attempts + 1
			WHERE id = %d AND stage = %s AND attempts < %d AND expires_at > %s",
			(int) $pending->id, $pending->stage, (int) $limit, gmdate('Y-m-d H:i:s')
		));
	}

	/**
	 * Claim a verified login once, against the current credential generation.
	 */
	public static function claim_pending($pending) {
		global $wpdb;

		$table       = JMFA_DB::table(JMFA_DB::PENDING);
		$credentials = JMFA_DB::table(JMFA_DB::CREDENTIALS);

		return 1 === $wpdb->query($wpdb->prepare(
			"DELETE p FROM {$table} AS p INNER JOIN {$credentials} AS c ON c.user_id = p.user_id
			WHERE p.id = %d AND p.stage = %s AND p.generation = c.generation
				AND c.state = 'enabled' AND p.expires_at > %s",
			(int) $pending->id, $pending->stage, gmdate('Y-m-d H:i:s')
		));
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

}
