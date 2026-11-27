<?php
/**
 * Enrolment helpers shared by the login interstitial and the admin screen.
 *
 * @package jPlugin-MFA
 */

if (!defined('ABSPATH')) {
	exit;
}

class JMFA_Enroll {

	const SETUP_TTL = 900;

	/**
	 * Start self-service setup in the current WordPress session.
	 */
	public static function start($user_id) {
		$row = JMFA_Store::credential($user_id, true);
		$key = self::admin_setup_key($user_id);

		if (!$row || 'enabled' === $row->state || '' === $key) {
			return false;
		}

		$sealed = JMFA_Crypto::encrypt(JMFA_TOTP::generate_secret());

		return false !== $sealed && set_transient(
			$key, array('secret' => $sealed, 'generation' => $row->generation), self::SETUP_TTL
		);
	}

	/**
	 * Read setup in this session while its credential generation is current.
	 */
	public static function admin_setup($user_id) {
		$key   = self::admin_setup_key($user_id);
		$setup = '' === $key ? false : get_transient($key);
		$row   = is_array($setup) ? JMFA_Store::credential($user_id) : false;

		if (!$row || 'enabled' === $row->state || $row->generation !== $setup['generation']) {
			return false;
		}

		$secret = JMFA_Crypto::decrypt($setup['secret']);

		return false === $secret ? false : array('secret' => $secret, 'generation' => $row->generation);
	}

	private static function admin_setup_key($user_id) {
		$token = wp_get_session_token();

		return '' === $token ? '' : 'jmfa_setup_' . (int) $user_id . '_' . hash('sha256', $token);
	}

	public static function finish_admin_setup($user_id) {
		$key = self::admin_setup_key($user_id);
		if ('' !== $key) {
			delete_transient($key);
		}
	}

	/**
	 * Confirm an enrolment with one valid code and turn MFA on.
	 *
	 * @param int          $user_id    User ID.
	 * @param string       $code       Six digit code from the app.
	 * @param string       $generation Credential generation from setup.
	 * @param string|false $secret     Setup secret.
	 * @param object|null  $pending    Native login challenge, if any.
	 * @return array|WP_Error Plain recovery codes on success.
	 */
	public static function confirm($user_id, $code, $generation, $secret, $pending = null) {
		$user_id = (int) $user_id;

		if (false === $secret) {
			return new WP_Error('jmfa_no_setup', __('หน้าการตั้งค่าหมดอายุแล้ว กรุณาเริ่มตั้งค่าใหม่', 'jplugin-mfa'));
		}

		$step = JMFA_TOTP::verify($secret, $code, (int) JMFA_Policy::get('window', 1), 0);

		if (false === $step) {
			return new WP_Error('jmfa_bad_code', __('รหัสไม่ถูกต้อง หรือเวลาในอุปกรณ์ไม่ตรงกับเซิร์ฟเวอร์', 'jplugin-mfa'));
		}

		$codes = JMFA_Store::generate_recovery_codes();

		if (!JMFA_Store::enable($user_id, $generation, $secret, $step, $codes, $pending)) {
			return new WP_Error('jmfa_save', __('บันทึกการตั้งค่าไม่สำเร็จ กรุณาลองใหม่', 'jplugin-mfa'));
		}

		JMFA_Audit::log('enrolled', $user_id);

		return $codes;
	}

	/**
	 * @param WP_User $user   User object.
	 * @param string  $secret Base32 secret.
	 * @return string otpauth:// URI.
	 */
	public static function provisioning_uri($user, $secret) {
		return JMFA_TOTP::provisioning_uri($secret, $user->user_login, JMFA_Policy::issuer());
	}

	/**
	 * Turn MFA off and drop the user's other sessions.
	 *
	 * @param int  $user_id      User ID.
	 * @param bool        $keep_current Keep the session that made the request.
	 * @param string|null $generation   Expected credential for self-service.
	 * @return bool
	 */
	public static function disable($user_id, $keep_current = false, $generation = null) {
		$user_id = (int) $user_id;

		if (!JMFA_Store::disable($user_id, $generation)) {
			return false;
		}

		JMFA_Audit::log('disabled', $user_id);

		self::destroy_sessions($user_id, $keep_current);

		return true;
	}

	/**
	 * Invalidate sessions of a user (used when MFA changes).
	 *
	 * @param int  $user_id      User ID.
	 * @param bool $keep_current Keep the session that made the request.
	 */
	public static function destroy_sessions($user_id, $keep_current = false) {
		$user_id = (int) $user_id;

		if (!class_exists('WP_Session_Tokens')) {
			return;
		}

		$manager = WP_Session_Tokens::get_instance($user_id);

		if ($keep_current) {
			$token = wp_get_session_token();

			if ($token) {
				$manager->destroy_others($token);

				return;
			}
		}

		$manager->destroy_all();
	}
}
