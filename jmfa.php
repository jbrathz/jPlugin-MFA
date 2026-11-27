<?php
/**
 * Plugin Name:       jPlugin-MFA - Two-Factor for WordPress Login
 * Plugin URI:        https://www.jirathsoft.com
 * Description:       Two-factor authentication (TOTP) for the native WordPress login. Standalone: WordPress core only, no other plugin is required or touched.
 * Version:           1.0.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            JIRATH BURAPARATH
 * Author URI:        https://www.jirathsoft.com
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       jplugin-mfa
 * Domain Path:       /languages
 *
 * @package jPlugin-MFA
 */

if (!defined('ABSPATH')) {
	exit;
}

define('JMFA_VERSION', '1.0.0');
define('JMFA_DB_VERSION', '1.0');
define('JMFA_FILE', __FILE__);
define('JMFA_PATH', plugin_dir_path(__FILE__));
define('JMFA_URL', plugin_dir_url(__FILE__));

require_once JMFA_PATH . 'includes/class-jmfa-db.php';
require_once JMFA_PATH . 'includes/class-jmfa-crypto.php';
require_once JMFA_PATH . 'includes/class-jmfa-totp.php';
require_once JMFA_PATH . 'includes/class-jmfa-audit.php';
require_once JMFA_PATH . 'includes/class-jmfa-store.php';
require_once JMFA_PATH . 'includes/class-jmfa-rate-limit.php';
require_once JMFA_PATH . 'includes/class-jmfa-policy.php';
require_once JMFA_PATH . 'includes/class-jmfa-enroll.php';
require_once JMFA_PATH . 'includes/class-jmfa-login.php';
require_once JMFA_PATH . 'includes/class-jmfa-plugin.php';

if (is_admin()) {
	require_once JMFA_PATH . 'admin/class-jmfa-admin.php';
	require_once JMFA_PATH . 'admin/class-jmfa-users.php';
}

if (defined('WP_CLI') && WP_CLI) {
	require_once JMFA_PATH . 'includes/class-jmfa-cli.php';
}

register_activation_hook(__FILE__, array('JMFA_Plugin', 'activate'));
register_deactivation_hook(__FILE__, array('JMFA_Plugin', 'deactivate'));

JMFA_Plugin::instance();