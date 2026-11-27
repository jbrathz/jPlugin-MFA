<?php
/**
 * Settings and the decision "does this user need a second factor?".
 *
 * @package jPlugin-MFA
 */

if (!defined('ABSPATH')) {
	exit;
}

class JMFA_Policy {

	const OPTION = 'jmfa_settings';

	const MODE_OFF      = 'off';
	const MODE_OPTIONAL = 'optional';
	const MODE_REQUIRED = 'required';

	/**
	 * @return array
	 */
	public static function defaults() {
		return array(
			'mode'                => self::MODE_OFF,
			'roles'               => array('administrator'),
			'window'              => 1,
			'max_attempts'        => 5,
			'allow_app_passwords' => false,
			'bind_ip'             => false,
			'log_retention'       => 90,
			'purge_on_uninstall'  => false,
			'issuer'              => '',
		);
	}

	/**
	 * @return array
	 */
	public static function all() {
		$saved = get_option(self::OPTION, array());

		if (!is_array($saved)) {
			$saved = array();
		}

		$settings = wp_parse_args($saved, self::defaults());

		$settings['roles'] = array_values(array_filter((array) $settings['roles'], 'is_string'));

		if (!$settings['roles']) {
			$settings['roles'] = array('administrator');
		}

		return $settings;
	}

	/**
	 * @param string $key     Setting key.
	 * @param mixed  $default Fallback.
	 * @return mixed
	 */
	public static function get($key, $default = null) {
		$all = self::all();

		return array_key_exists($key, $all) ? $all[ $key ] : $default;
	}

	/**
	 * Break glass switch: define('JMFA_DISABLE', true) in wp-config.php.
	 *
	 * @return bool
	 */
	public static function is_disabled() {
		return defined('JMFA_DISABLE') && JMFA_DISABLE;
	}

	/**
	 * @return string Issuer label shown in the authenticator app.
	 */
	public static function issuer() {
		$issuer = trim((string) self::get('issuer', ''));

		if ('' === $issuer) {
			$issuer = wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES);
		}

		$issuer = trim(preg_replace('/[\x00-\x1F\x7F]/u', '', $issuer));

		if ('' === $issuer) {
			$issuer = 'WordPress';
		}

		return mb_substr($issuer, 0, 60);
	}

	/**
	 * @param WP_User $user User object.
	 * @return bool True when the user has one of the configured roles.
	 */
	public static function role_applies($user) {
		if (!($user instanceof WP_User)) {
			return false;
		}

		$roles      = (array) self::get('roles', array('administrator'));
		$user_roles = (array) $user->roles;
		$applies    = (bool) array_intersect($roles, $user_roles);

		return (bool) apply_filters('jmfa_user_in_scope', $applies, $user);
	}

	/**
	 * Should this user pass a second step before receiving a session?
	 *
	 * @param WP_User $user User object.
	 * @return bool
	 */
	public static function requires_gate($user) {
		if (self::is_disabled()) {
			return false;
		}

		if (!($user instanceof WP_User)) {
			return false;
		}

		$mode = (string) self::get('mode', self::MODE_OFF);

		if (self::MODE_OFF === $mode) {
			return false;
		}

		if (JMFA_Store::is_enabled($user->ID)) {
			return (bool) apply_filters('jmfa_user_requires_mfa', true, $user);
		}

		if (self::MODE_REQUIRED === $mode && self::role_applies($user)) {
			return (bool) apply_filters('jmfa_user_requires_mfa', true, $user);
		}

		return false;
	}
}