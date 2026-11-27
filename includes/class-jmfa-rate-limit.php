<?php
/**
 * Simple transient counter used for throttling.
 *
 * @package jPlugin-MFA
 */

if (!defined('ABSPATH')) {
	exit;
}

class JMFA_Rate_Limit {

	/**
	 * Count a hit and report whether the caller is still inside the limit.
	 *
	 * @param string $key    Logical bucket.
	 * @param int    $limit  Allowed hits per window.
	 * @param int    $window Window in seconds.
	 * @return bool
	 */
	public static function allow($key, $limit, $window) {
		$name = 'jmfa_rl_' . md5((string) $key);
		$data = get_transient($name);

		if (!is_array($data) || !isset($data['count'])) {
			$data = array('count' => 0);
		}

		$data['count']++;
		set_transient($name, $data, max(60, (int) $window));

		return $data['count'] <= (int) $limit;
	}

	/**
	 * @param string $key Logical bucket.
	 * @return int Hits inside the current window.
	 */
	public static function peek($key) {
		$data = get_transient('jmfa_rl_' . md5((string) $key));

		return (is_array($data) && isset($data['count'])) ? (int) $data['count'] : 0;
	}

	/**
	 * @param string $key Logical bucket.
	 */
	public static function clear($key) {
		delete_transient('jmfa_rl_' . md5((string) $key));
	}
}