<?php
/**
 * Uninstall routine.
 *
 * Nothing is removed unless the site owner explicitly enabled
 * "purge on uninstall". Deactivating the plugin never deletes data.
 *
 * @package jPlugin-MFA
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
	exit;
}

$jmfa_settings = get_option('jmfa_settings', array());

if (!is_array($jmfa_settings) || empty($jmfa_settings['purge_on_uninstall'])) {
	return;
}

global $wpdb;

$wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}jmfa_pending");
$wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}jmfa_log");

delete_option('jmfa_settings');
delete_option('jmfa_db_version');

$jmfa_meta_keys = array(
	'_jmfa_status',
	'_jmfa_secret',
	'_jmfa_last_step',
	'_jmfa_recovery',
	'_jmfa_enrolled_at',
	'_jmfa_setup',
	'_jmfa_setup_expires',
);

foreach ($jmfa_meta_keys as $jmfa_key) {
	delete_metadata('user', 0, $jmfa_key, '', true);
}

wp_clear_scheduled_hook('jmfa_prune');