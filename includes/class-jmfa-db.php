<?php
/**
 * Database schema.
 *
 * Two private tables only. No table of any other plugin is read or written.
 *
 * @package jPlugin-MFA
 */

if (!defined('ABSPATH')) {
	exit;
}

class JMFA_DB {

	const PENDING       = 'jmfa_pending';
	const LOG           = 'jmfa_log';
	const VERSION_OPTION = 'jmfa_db_version';

	/**
	 * Fully prefixed table name.
	 *
	 * @param string $name Table short name.
	 * @return string
	 */
	public static function table($name) {
		global $wpdb;
		return $wpdb->prefix . $name;
	}

	/**
	 * Create or upgrade the plugin tables. Safe to call repeatedly (dbDelta).
	 */
	public static function install() {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset_collate = $wpdb->get_charset_collate();
		$pending         = self::table(self::PENDING);
		$log             = self::table(self::LOG);

		dbDelta(
			"CREATE TABLE {$pending} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				token_hash char(64) NOT NULL,
				user_id bigint(20) unsigned NOT NULL DEFAULT 0,
				stage varchar(16) NOT NULL DEFAULT 'verify',
				remember tinyint(1) NOT NULL DEFAULT 0,
				redirect_to varchar(255) NOT NULL DEFAULT '',
				ip_hash char(64) NOT NULL DEFAULT '',
				ua_hash char(64) NOT NULL DEFAULT '',
				attempts smallint(5) unsigned NOT NULL DEFAULT 0,
				created_at datetime NOT NULL,
				expires_at datetime NOT NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY token_hash (token_hash),
				KEY user_id (user_id),
				KEY expires_at (expires_at)
			) {$charset_collate};"
		);

		dbDelta(
			"CREATE TABLE {$log} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				user_id bigint(20) unsigned NOT NULL DEFAULT 0,
				event varchar(32) NOT NULL DEFAULT '',
				ip_hash char(64) NOT NULL DEFAULT '',
				ua_hash char(64) NOT NULL DEFAULT '',
				context text NULL,
				created_at datetime NOT NULL,
				PRIMARY KEY  (id),
				KEY user_id (user_id),
				KEY event (event),
				KEY created_at (created_at)
			) {$charset_collate};"
		);

		update_option(self::VERSION_OPTION, JMFA_DB_VERSION);
	}

	/**
	 * Run the installer when the stored schema version differs or a table is missing.
	 */
	public static function maybe_upgrade() {
		if (get_option(self::VERSION_OPTION) === JMFA_DB_VERSION) {
			return;
		}

		self::install();
	}

	/**
	 * @param string $name Table short name.
	 * @return bool
	 */
	public static function table_exists($name) {
		global $wpdb;

		$table = self::table($name);
		$found = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($table)));

		return $found === $table;
	}
}