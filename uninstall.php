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

global $wpdb;

$jmfa_multisite = is_multisite();
$jmfa_site_ids  = $jmfa_multisite ? get_sites(array('fields' => 'ids', 'number' => 0)) : array(get_current_blog_id());
$jmfa_cleaned   = false;
$jmfa_keep_user_data = false;

foreach ($jmfa_site_ids as $jmfa_site_id) {
	if ($jmfa_multisite) {
		switch_to_blog($jmfa_site_id);
	}

	$jmfa_settings = get_option('jmfa_settings', null);
	if (!empty($jmfa_settings['purge_on_uninstall'])) {
		$wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}jmfa_pending");
		$wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}jmfa_log");

		delete_option('jmfa_settings');
		delete_option('jmfa_db_version');
		delete_option('jmfa_last_prune');
		wp_clear_scheduled_hook('jmfa_prune');
		$jmfa_cleaned = true;
	} elseif (null !== $jmfa_settings || get_option('jmfa_db_version')) {
		$jmfa_keep_user_data = true;
	}

	if ($jmfa_multisite) {
		restore_current_blog();
	}
}

// All sites with jPlugin-MFA data must opt in before removing shared credentials.
if (!$jmfa_cleaned || $jmfa_keep_user_data) {
	return;
}

$wpdb->query("DROP TABLE IF EXISTS {$wpdb->base_prefix}jmfa_credentials");

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
