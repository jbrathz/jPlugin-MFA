<?php
/**
 * Database schema.
 *
 * Plugin-owned pending, audit and credential tables.
 *
 * @package jPlugin-MFA
 */

if (!defined('ABSPATH')) {
	exit;
}

class JMFA_DB {

	const PENDING       = 'jmfa_pending';
	const LOG           = 'jmfa_log';
	const CREDENTIALS   = 'jmfa_credentials';
	const VERSION_OPTION = 'jmfa_db_version';

	/**
	 * Fully prefixed table name.
	 *
	 * @param string $name Table short name.
	 * @return string
	 */
	public static function table($name) {
		global $wpdb;
		if (self::CREDENTIALS === $name) {
			// The legacy credentials are user meta, shared by all sites on a network.
			return $wpdb->base_prefix . $name;
		}

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
		$credentials     = self::table(self::CREDENTIALS);

		dbDelta(
			"CREATE TABLE {$pending} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				token_hash char(64) NOT NULL,
				user_id bigint(20) unsigned NOT NULL DEFAULT 0,
				stage varchar(16) NOT NULL DEFAULT 'verify',
				remember tinyint(1) NOT NULL DEFAULT 0,
				redirect_to text NOT NULL,
				generation char(32) NOT NULL DEFAULT '',
				setup_secret text NULL,
				login_context text NULL,
				ip_hash char(64) NOT NULL DEFAULT '',
				ua_hash char(64) NOT NULL DEFAULT '',
				attempts smallint(5) unsigned NOT NULL DEFAULT 0,
				created_at datetime NOT NULL,
				expires_at datetime NOT NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY token_hash (token_hash),
				KEY user_id (user_id),
				KEY expires_at (expires_at)
			) ENGINE=InnoDB {$charset_collate};"
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

		dbDelta(
			"CREATE TABLE {$credentials} (
				user_id bigint(20) unsigned NOT NULL,
				state varchar(8) NOT NULL DEFAULT '',
				generation char(32) NOT NULL,
				secret text NOT NULL,
				last_step bigint(20) unsigned NOT NULL DEFAULT 0,
				recovery text NOT NULL,
				PRIMARY KEY  (user_id),
				KEY state (state)
			) ENGINE=InnoDB {$charset_collate};"
		);

		$columns = $wpdb->get_col("SHOW COLUMNS FROM {$pending}");
		$engine  = $wpdb->get_row($wpdb->prepare('SHOW TABLE STATUS WHERE Name = %s', $pending));
		$atomic  = $engine && ('InnoDB' === $engine->Engine || false !== $wpdb->query("ALTER TABLE {$pending} ENGINE=InnoDB"));

		if ($atomic && self::table_exists(self::CREDENTIALS) && self::table_exists(self::LOG)
			&& !array_diff(array('generation', 'setup_secret', 'login_context'), $columns)) {
			update_option(self::VERSION_OPTION, JMFA_DB_VERSION);
		}
	}

	/**
	 * Run the installer when the stored schema version differs.
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
