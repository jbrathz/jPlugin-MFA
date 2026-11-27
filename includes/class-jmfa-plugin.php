<?php
/**
 * Bootstrap and lifecycle hooks.
 *
 * Activation only creates the plugin's own tables and a default "off" setting,
 * deactivation removes nothing but its own transient login state, so the site
 * behaves exactly as before whenever the plugin is switched off.
 *
 * @package jPlugin-MFA
 */

if (!defined('ABSPATH')) {
	exit;
}

class JMFA_Plugin {

	/**
	 * @var JMFA_Plugin|null
	 */
	private static $instance = null;

	/**
	 * @return JMFA_Plugin
	 */
	public static function instance() {
		if (null === self::$instance) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {
		add_action('plugins_loaded', array($this, 'boot'));
	}

	/**
	 * Wire the runtime hooks.
	 */
	public function boot() {
		load_plugin_textdomain('jplugin-mfa', false, dirname(plugin_basename(JMFA_FILE)) . '/languages');

		JMFA_DB::maybe_upgrade();
		JMFA_Login::init();

		if (is_admin()) {
			if (class_exists('JMFA_Admin')) {
				JMFA_Admin::init();
			}

			if (class_exists('JMFA_Users')) {
				JMFA_Users::init();
			}
		}

		add_action('jmfa_prune', array('JMFA_Store', 'prune'));
		add_action('init', array($this, 'maybe_prune'), 20);

		if (!wp_next_scheduled('jmfa_prune')) {
			wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', 'jmfa_prune');
		}
	}

	/**
	 * Safety net for the retention window.
	 *
	 * WP-Cron only runs when the site gets traffic, and it is disabled on some
	 * hosts, so the cleanup also runs inline at most every six hours. That makes
	 * "delete after N days" a guarantee rather than a best effort.
	 */
	public function maybe_prune() {
		$last = (int) get_option('jmfa_last_prune', 0);

		if ($last > 0 && (time() - $last) < (6 * HOUR_IN_SECONDS)) {
			return;
		}

		JMFA_Store::prune();
	}

	/**
	 * Activation: own tables plus a default configuration that changes nothing.
	 */
	public static function activate() {
		JMFA_DB::install();

		$settings = get_option(JMFA_Policy::OPTION, null);

		if (!is_array($settings)) {
			add_option(JMFA_Policy::OPTION, JMFA_Policy::defaults(), '', 'yes');
		}

		add_option('jmfa_last_prune', 0, '', 'no');

		if (!wp_next_scheduled('jmfa_prune')) {
			wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', 'jmfa_prune');
		}
	}

	/**
	 * Deactivation: drop transient login state only. Secrets, recovery codes,
	 * settings and audit history are kept so re-activation is seamless.
	 */
	public static function deactivate() {
		JMFA_Store::purge_pending();
		JMFA_Login::clear_cookie();
		wp_clear_scheduled_hook('jmfa_prune');
	}
}