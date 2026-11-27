<?php
/**
 * Users list column and profile section.
 *
 * @package jPlugin-MFA
 */

if (!defined('ABSPATH')) {
	exit;
}

class JMFA_Users {

	public static function init() {
		add_filter('manage_users_columns', array(__CLASS__, 'column'));
		add_filter('manage_users_custom_column', array(__CLASS__, 'column_value'), 10, 3);
		add_action('show_user_profile', array(__CLASS__, 'profile_section'));
		add_action('edit_user_profile', array(__CLASS__, 'profile_section'));
	}

	/**
	 * @param array $columns Columns.
	 * @return array
	 */
	public static function column($columns) {
		$columns['jmfa'] = __('MFA', 'jplugin-mfa');

		return $columns;
	}

	/**
	 * @param string $value   Cell content.
	 * @param string $column  Column key.
	 * @param int    $user_id User ID.
	 * @return string
	 */
	public static function column_value($value, $column, $user_id) {
		if ('jmfa' !== $column) {
			return $value;
		}

		if (JMFA_Store::is_enabled($user_id)) {
			return '<span class="jmfa-badge jmfa-badge-on">' . esc_html__('เปิด', 'jplugin-mfa') . '</span>';
		}

		return '<span class="jmfa-badge jmfa-badge-off">—</span>';
	}

	/**
	 * @param WP_User $user Profile owner.
	 */
	public static function profile_section($user) {
		if (!($user instanceof WP_User)) {
			return;
		}

		$is_self = ((int) $user->ID === get_current_user_id());

		if (!$is_self && !current_user_can('manage_options')) {
			return;
		}

		$enabled = JMFA_Store::is_enabled($user->ID);
		?>
		<h2><?php esc_html_e('การยืนยันตัวตนสองขั้น (jPlugin-MFA)', 'jplugin-mfa'); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th><?php esc_html_e('สถานะ', 'jplugin-mfa'); ?></th>
				<td>
					<?php if ($enabled) : ?>
						<span class="jmfa-badge jmfa-badge-on"><?php esc_html_e('เปิดใช้งาน', 'jplugin-mfa'); ?></span>
						<span class="description">
							<?php
							echo esc_html(
								sprintf(
									/* translators: %d: remaining codes */
									__('· รหัสสำรองเหลือ %d รหัส', 'jplugin-mfa'),
									JMFA_Store::recovery_remaining($user->ID)
								)
							);
							?>
						</span>
					<?php else : ?>
						<span class="jmfa-badge jmfa-badge-off"><?php esc_html_e('ยังไม่ตั้งค่า', 'jplugin-mfa'); ?></span>
					<?php endif; ?>

					<?php if ($is_self && current_user_can('manage_options')) : ?>
						<p>
							<a class="button" href="<?php echo esc_url(JMFA_Admin::tab_url('me')); ?>">
								<?php esc_html_e('จัดการการยืนยันตัวตนสองขั้น', 'jplugin-mfa'); ?>
							</a>
						</p>
					<?php endif; ?>
				</td>
			</tr>
		</table>
		<?php
	}
}