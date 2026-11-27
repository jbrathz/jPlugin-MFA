<?php
/**
 * Audit trail.
 *
 * Stores hashed client identifiers only: no IP address or user agent is kept
 * in clear text.
 *
 * @package jPlugin-MFA
 */

if (!defined('ABSPATH')) {
	exit;
}

class JMFA_Audit {

	/**
	 * @param string $event   Short event key.
	 * @param int    $user_id Related user, 0 when unknown.
	 * @param array  $context Extra data, stored as JSON.
	 */
	public static function log($event, $user_id = 0, array $context = array()) {
		global $wpdb;

		if (!JMFA_DB::table_exists(JMFA_DB::LOG)) {
			return;
		}

		$wpdb->insert(
			JMFA_DB::table(JMFA_DB::LOG),
			array(
				'user_id'    => (int) $user_id,
				'event'      => substr(sanitize_key((string) $event), 0, 32),
				'ip_hash'    => self::ip_hash(),
				'ua_hash'    => self::ua_hash(),
				'context'    => $context ? wp_json_encode($context) : null,
				'created_at' => gmdate('Y-m-d H:i:s'),
			),
			array('%d', '%s', '%s', '%s', '%s', '%s')
		);
	}

	/**
	 * @return string Client address, or "unknown".
	 */
	public static function client_ip() {
		$ip = isset($_SERVER['REMOTE_ADDR']) ? (string) $_SERVER['REMOTE_ADDR'] : '';

		return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : 'unknown';
	}

	/**
	 * @return string Non reversible identifier.
	 */
	public static function ip_hash() {
		return wp_hash('jmfa-ip|' . self::client_ip());
	}

	/**
	 * @return string Non reversible identifier.
	 */
	public static function ua_hash() {
		$agent = isset($_SERVER['HTTP_USER_AGENT']) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';

		return wp_hash('jmfa-ua|' . substr($agent, 0, 255));
	}

	/**
	 * @param int $limit  Rows to return.
	 * @param int $offset Offset.
	 * @return array
	 */
	public static function recent($limit = 100, $offset = 0) {
		global $wpdb;

		if (!JMFA_DB::table_exists(JMFA_DB::LOG)) {
			return array();
		}

		$table = JMFA_DB::table(JMFA_DB::LOG);
		$rows  = $wpdb->get_results(
			$wpdb->prepare("SELECT * FROM {$table} ORDER BY id DESC LIMIT %d OFFSET %d", max(1, (int) $limit), max(0, (int) $offset))
		);

		return is_array($rows) ? $rows : array();
	}

	/**
	 * @return int
	 */
	public static function count() {
		global $wpdb;

		if (!JMFA_DB::table_exists(JMFA_DB::LOG)) {
			return 0;
		}

		$table = JMFA_DB::table(JMFA_DB::LOG);

		return (int) $wpdb->get_var("SELECT COUNT(*) FROM {$table}");
	}

	/**
	 * Drop entries older than the retention window.
	 *
	 * @param int $days Retention in days.
	 */
	public static function prune($days) {
		global $wpdb;

		$days = max(1, (int) $days);

		if (!JMFA_DB::table_exists(JMFA_DB::LOG)) {
			return;
		}

		$table = JMFA_DB::table(JMFA_DB::LOG);

		$wpdb->query(
			$wpdb->prepare("DELETE FROM {$table} WHERE created_at < %s", gmdate('Y-m-d H:i:s', time() - ($days * DAY_IN_SECONDS)))
		);
	}

	/**
	 * Human readable labels for the events this plugin writes.
	 *
	 * @return array
	 */
	public static function labels() {
		return array(
			'password_ok'          => __('ผ่านขั้นรหัสผ่าน', 'jplugin-mfa'),
			'verify_ok'            => __('ยืนยันรหัสถูกต้อง', 'jplugin-mfa'),
			'verify_fail'          => __('กรอกรหัสผิด', 'jplugin-mfa'),
			'login_ok'             => __('เข้าสู่ระบบสำเร็จ', 'jplugin-mfa'),
			'login_ok_recovery'    => __('เข้าสู่ระบบด้วยรหัสสำรอง', 'jplugin-mfa'),
			'recovery_used'        => __('ใช้รหัสสำรอง', 'jplugin-mfa'),
			'recovery_regenerated' => __('สร้างรหัสสำรองชุดใหม่', 'jplugin-mfa'),
			'enrolled'             => __('เปิดใช้งาน MFA', 'jplugin-mfa'),
			'disabled'             => __('ปิดการใช้งาน MFA', 'jplugin-mfa'),
			'locked'               => __('ถูกล็อกจากการกรอกผิดหลายครั้ง', 'jplugin-mfa'),
			'blocked_non_web'      => __('บล็อกการเข้าจาก XML-RPC/REST', 'jplugin-mfa'),
			'bypass_app_password'  => __('ผ่านด้วย Application Password', 'jplugin-mfa'),
			'throttled'            => __('ถูกจำกัดอัตราคำขอ', 'jplugin-mfa'),
			'ip_mismatch'          => __('เครือข่ายเปลี่ยนกลางคัน', 'jplugin-mfa'),
			'secret_unreadable'    => __('อ่านค่าความลับไม่ได้', 'jplugin-mfa'),
			'settings_saved'       => __('บันทึกการตั้งค่า', 'jplugin-mfa'),
			'admin_reset'          => __('แอดมินรีเซ็ต MFA', 'jplugin-mfa'),
			'admin_unlock'         => __('แอดมินล้างรายการค้าง', 'jplugin-mfa'),
			'cli_reset'            => __('รีเซ็ตผ่าน WP-CLI', 'jplugin-mfa'),
			'logout'               => __('ออกจากระบบ', 'jplugin-mfa'),
		);
	}

	/**
	 * @param string $event Event key.
	 * @return string
	 */
	public static function label($event) {
		$labels = self::labels();

		return isset($labels[ $event ]) ? $labels[ $event ] : (string) $event;
	}

	/**
	 * Rows for the CSV report, newest first.
	 *
	 * @param int $days  Only rows newer than this many days, 0 for everything kept.
	 * @param int $limit Hard cap on exported rows.
	 * @return array
	 */
	public static function export($days = 0, $limit = 50000) {
		global $wpdb;

		if (!JMFA_DB::table_exists(JMFA_DB::LOG)) {
			return array();
		}

		$table = JMFA_DB::table(JMFA_DB::LOG);
		$users = $wpdb->users;
		$where = '1=1';
		$args  = array();

		if ((int) $days > 0) {
			$where .= ' AND l.created_at >= %s';
			$args[] = gmdate('Y-m-d H:i:s', time() - ((int) $days * DAY_IN_SECONDS));
		}

		$args[] = max(1, (int) $limit);

		$sql = "SELECT l.*, u.user_login FROM {$table} l LEFT JOIN {$users} u ON u.ID = l.user_id WHERE {$where} ORDER BY l.id DESC LIMIT %d";

		return (array) $wpdb->get_results($wpdb->prepare($sql, $args));
	}
}