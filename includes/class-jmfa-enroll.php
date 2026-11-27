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
	 * Secret for an in progress enrolment. Reuses the same one until it expires
	 * so refreshing the page does not invalidate an already scanned QR code.
	 *
	 * @param int $user_id User ID.
	 * @return string|false Base32 secret.
	 */
	public static function secret_for_user($user_id) {
		$user_id = (int) $user_id;
		$secret  = self::peek_secret($user_id);

		if (false !== $secret) {
			return $secret;
		}

		$secret = JMFA_TOTP::generate_secret();
		$sealed = JMFA_Crypto::encrypt($secret);

		if (false === $sealed) {
			return false;
		}

		update_user_meta($user_id, JMFA_Store::META_SETUP, $sealed);
		update_user_meta($user_id, JMFA_Store::META_SETUP_EXPIRES, time() + self::SETUP_TTL);

		return $secret;
	}

	/**
	 * Read a non expired enrolment secret without creating one.
	 *
	 * @param int $user_id User ID.
	 * @return string|false
	 */
	public static function peek_secret($user_id) {
		$user_id = (int) $user_id;
		$stored  = (string) get_user_meta($user_id, JMFA_Store::META_SETUP, true);
		$expires = (int) get_user_meta($user_id, JMFA_Store::META_SETUP_EXPIRES, true);

		if ('' === $stored || $expires <= time()) {
			return false;
		}

		$plain = JMFA_Crypto::decrypt($stored);

		return (is_string($plain) && '' !== $plain) ? $plain : false;
	}

	/**
	 * Confirm an enrolment with one valid code and turn MFA on.
	 *
	 * @param int    $user_id User ID.
	 * @param string $code    Six digit code from the app.
	 * @return array|WP_Error Plain recovery codes on success.
	 */
	public static function confirm($user_id, $code) {
		$user_id = (int) $user_id;
		$secret  = self::peek_secret($user_id);

		if (false === $secret) {
			return new WP_Error('jmfa_no_setup', __('หน้าการตั้งค่าหมดอายุแล้ว กรุณาเริ่มตั้งค่าใหม่', 'jplugin-mfa'));
		}

		$step = JMFA_TOTP::verify($secret, $code, (int) JMFA_Policy::get('window', 1), 0);

		if (false === $step) {
			return new WP_Error('jmfa_bad_code', __('รหัสไม่ถูกต้อง หรือเวลาในอุปกรณ์ไม่ตรงกับเซิร์ฟเวอร์', 'jplugin-mfa'));
		}

		$codes = JMFA_Store::generate_recovery_codes();

		if (!JMFA_Store::enable($user_id, $secret, $step, $codes)) {
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
	 * @param bool $keep_current Keep the session that made the request.
	 */
	public static function disable($user_id, $keep_current = false) {
		$user_id = (int) $user_id;

		JMFA_Store::disable($user_id);
		JMFA_Audit::log('disabled', $user_id);

		self::destroy_sessions($user_id, $keep_current);
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