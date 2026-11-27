<?php
/**
 * Admin screens and form handlers.
 *
 * @package jPlugin-MFA
 */

if (!defined('ABSPATH')) {
	exit;
}

class JMFA_Admin {

	const SLUG = 'jmfa';
	const SELF_SLUG = 'jmfa-me';

	/**
	 * Register hooks.
	 */
	public static function init() {
		add_action('admin_menu', array(__CLASS__, 'menu'));
		add_action('admin_enqueue_scripts', array(__CLASS__, 'assets'));
		add_action('admin_notices', array(__CLASS__, 'notices'));

		add_action('admin_post_jmfa_save_settings', array(__CLASS__, 'handle_save_settings'));
		add_action('admin_post_jmfa_start_enroll', array(__CLASS__, 'handle_start_enroll'));
		add_action('admin_post_jmfa_confirm_enroll', array(__CLASS__, 'handle_confirm_enroll'));
		add_action('admin_post_jmfa_disable', array(__CLASS__, 'handle_disable'));
		add_action('admin_post_jmfa_regen', array(__CLASS__, 'handle_regen'));
		add_action('admin_post_jmfa_reset_user', array(__CLASS__, 'handle_reset_user'));
		add_action('admin_post_jmfa_unlock_user', array(__CLASS__, 'handle_unlock_user'));
		add_action('admin_post_jmfa_export_log', array(__CLASS__, 'handle_export_log'));
	}

	public static function menu() {
		if (!current_user_can('manage_options')) {
			add_submenu_page(
				'profile.php',
				__('ความปลอดภัยของฉัน', 'jplugin-mfa'),
				__('ความปลอดภัยของฉัน', 'jplugin-mfa'),
				'read',
				self::SELF_SLUG,
				array(__CLASS__, 'render_self')
			);
			return;
		}

		add_menu_page(
			__('jPlugin-MFA', 'jplugin-mfa'),
			__('jPlugin-MFA', 'jplugin-mfa'),
			'manage_options',
			self::SLUG,
			array(__CLASS__, 'render'),
			'dashicons-shield-alt',
			76
		);
	}

	/**
	 * @param string $hook Current admin page hook.
	 */
	public static function assets($hook) {
		if (!in_array($hook, array('toplevel_page_' . self::SLUG, 'profile_page_' . self::SELF_SLUG,
			'users_page_' . self::SELF_SLUG, 'admin_page_' . self::SELF_SLUG), true)) {
			return;
		}

		wp_enqueue_style('jmfa-admin', JMFA_URL . 'assets/css/jmfa.css', array(), JMFA_VERSION);
		wp_enqueue_script('jmfa-qr', JMFA_URL . 'assets/js/qrcode.js', array(), '1.4.4', true);
		wp_enqueue_script('jmfa-admin', JMFA_URL . 'assets/js/jmfa.js', array('jmfa-qr'), JMFA_VERSION, true);
	}

	/* ---------------------------------------------------------------------
	 * Router
	 * ------------------------------------------------------------------ */

	public static function render() {
		if (!current_user_can('manage_options')) {
			wp_die(esc_html__('ไม่มีสิทธิ์เข้าถึงหน้านี้', 'jplugin-mfa'));
		}

		$tab = isset($_GET['tab']) ? sanitize_key(wp_unslash($_GET['tab'])) : 'settings';

		echo '<div class="wrap jmfa-wrap">';
		echo '<h1>' . esc_html__('jPlugin-MFA — การยืนยันตัวตนสองขั้น', 'jplugin-mfa') . '</h1>';

		self::render_messages();
		self::render_tabs($tab);

		switch ($tab) {
			case 'me':
				self::render_me();
				break;
			case 'users':
				self::render_users();
				break;
			case 'log':
				self::render_log();
				break;
			default:
				self::render_settings();
		}

		echo '</div>';
	}

	public static function render_self() {
		self::require_self_access();
		echo '<div class="wrap jmfa-wrap">';
		echo '<h1>' . esc_html__('jPlugin-MFA — การยืนยันตัวตนสองขั้น', 'jplugin-mfa') . '</h1>';
		self::render_messages();
		self::render_me();
		echo '</div>';
	}

	/**
	 * @param string $tab Current tab.
	 */
	private static function render_tabs($tab) {
		$tabs = array(
			'settings' => __('การตั้งค่า', 'jplugin-mfa'),
			'me'       => __('ความปลอดภัยของฉัน', 'jplugin-mfa'),
			'users'    => __('ผู้ใช้', 'jplugin-mfa'),
			'log'      => __('บันทึกเหตุการณ์', 'jplugin-mfa'),
		);

		echo '<nav class="nav-tab-wrapper">';

		foreach ($tabs as $key => $label) {
			printf(
				'<a href="%1$s" class="nav-tab%2$s">%3$s</a>',
				esc_url(self::tab_url($key)),
				$key === $tab ? ' nav-tab-active' : '',
				esc_html($label)
			);
		}

		echo '</nav>';
	}

	private static function render_messages() {
		$message = isset($_GET['jmfa_msg']) ? sanitize_key(wp_unslash($_GET['jmfa_msg'])) : '';

		if ('' === $message) {
			return;
		}

		$texts = array(
			'saved'          => array('success', __('บันทึกการตั้งค่าแล้ว', 'jplugin-mfa')),
			'enrolled'       => array('success', __('เปิดใช้งานการยืนยันตัวตนสองขั้นแล้ว', 'jplugin-mfa')),
			'disabled'       => array('success', __('ปิดการยืนยันตัวตนสองขั้นของบัญชีนี้แล้ว', 'jplugin-mfa')),
			'regen'          => array('success', __('สร้างรหัสสำรองชุดใหม่แล้ว', 'jplugin-mfa')),
			'reset'          => array('success', __('รีเซ็ต MFA ของผู้ใช้แล้ว', 'jplugin-mfa')),
			'unlocked'       => array('success', __('ล้างการเข้าสู่ระบบที่ค้างอยู่แล้ว', 'jplugin-mfa')),
			'error'          => array('error', __('ทำรายการไม่สำเร็จ กรุณาลองใหม่', 'jplugin-mfa')),
			'code_error'     => array('error', __('รหัสไม่ถูกต้อง หรือเวลาในอุปกรณ์ไม่ตรงกับเซิร์ฟเวอร์', 'jplugin-mfa')),
			'codes_missing'  => array('warning', __('บันทึกการเปลี่ยนแปลงแล้ว แต่แสดงรหัสสำรองไม่ได้ กรุณาสร้างชุดใหม่จากหน้านี้', 'jplugin-mfa')),
		);

		if (!isset($texts[ $message ])) {
			return;
		}

		printf(
			'<div class="notice notice-%1$s is-dismissible"><p>%2$s</p></div>',
			esc_attr($texts[ $message ][0]),
			esc_html($texts[ $message ][1])
		);
	}

	/* ---------------------------------------------------------------------
	 * Tab: settings
	 * ------------------------------------------------------------------ */

	private static function render_settings() {
		$settings = JMFA_Policy::all();
		$roles    = wp_roles()->roles;
		?>
		<form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" class="jmfa-form">
			<input type="hidden" name="action" value="jmfa_save_settings" />
			<?php wp_nonce_field('jmfa_save_settings'); ?>

			<h2><?php esc_html_e('นโยบาย', 'jplugin-mfa'); ?></h2>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><?php esc_html_e('โหมดการทำงาน', 'jplugin-mfa'); ?></th>
					<td>
						<fieldset>
							<label>
								<input type="radio" name="jmfa_mode" value="off" <?php checked($settings['mode'], 'off'); ?> />
								<?php esc_html_e('ปิด — ไม่บังคับใคร และไม่ตรวจตอนเข้าสู่ระบบ', 'jplugin-mfa'); ?>
							</label><br />
							<label>
								<input type="radio" name="jmfa_mode" value="optional" <?php checked($settings['mode'], 'optional'); ?> />
								<?php esc_html_e('เปิดให้เลือก — เฉพาะผู้ใช้ที่ตั้งค่าเองแล้วเท่านั้นที่ต้องยืนยัน', 'jplugin-mfa'); ?>
							</label><br />
							<label>
								<input type="radio" name="jmfa_mode" value="required" <?php checked($settings['mode'], 'required'); ?> />
								<?php esc_html_e('บังคับ — ผู้ใช้ในบทบาทที่เลือกต้องตั้งค่าให้เสร็จก่อนเข้าสู่ระบบ', 'jplugin-mfa'); ?>
							</label>
						</fieldset>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e('บทบาทที่บังคับ', 'jplugin-mfa'); ?></th>
					<td>
						<fieldset>
							<?php foreach ($roles as $slug => $role) : ?>
								<label>
									<input type="checkbox" name="jmfa_roles[]" value="<?php echo esc_attr($slug); ?>"
										<?php checked(in_array($slug, (array) $settings['roles'], true)); ?> />
									<?php echo esc_html(translate_user_role($role['name'])); ?>
								</label><br />
							<?php endforeach; ?>
						</fieldset>
						<p class="description"><?php esc_html_e('ผู้ใช้ที่เปิด MFA เองแล้วจะยังถูกตรวจแม้ไม่ได้อยู่ในบทบาทเหล่านี้', 'jplugin-mfa'); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="jmfa_issuer"><?php esc_html_e('ชื่อที่แสดงในแอป', 'jplugin-mfa'); ?></label></th>
					<td>
						<input type="text" class="regular-text" id="jmfa_issuer" name="jmfa_issuer"
							value="<?php echo esc_attr($settings['issuer']); ?>" maxlength="60" />
						<p class="description"><?php esc_html_e('เว้นว่างเพื่อใช้ชื่อเว็บ', 'jplugin-mfa'); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e('ความเข้มงวดของรหัส', 'jplugin-mfa'); ?></th>
					<td>
						<label for="jmfa_window"><?php esc_html_e('ยอมรับเวลาคลาดเคลื่อน', 'jplugin-mfa'); ?></label>
						<select id="jmfa_window" name="jmfa_window">
							<?php for ($i = 0; $i <= 3; $i++) : ?>
								<option value="<?php echo esc_attr($i); ?>" <?php selected((int) $settings['window'], $i); ?>>
									<?php echo esc_html(sprintf(__('± %d step (%.0f วินาที)', 'jplugin-mfa'), $i, $i * 30)); ?>
								</option>
							<?php endfor; ?>
						</select>
						<p class="description"><?php esc_html_e('ค่าแนะนำคือ ±1 step ซึ่งรองรับนาฬิกาที่คลาดเคลื่อนเล็กน้อยโดยไม่เปิดช่องให้ใช้รหัสซ้ำ', 'jplugin-mfa'); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="jmfa_max_attempts"><?php esc_html_e('จำนวนครั้งที่กรอกผิดได้', 'jplugin-mfa'); ?></label></th>
					<td>
						<input type="number" class="small-text" id="jmfa_max_attempts" name="jmfa_max_attempts"
							value="<?php echo esc_attr((int) $settings['max_attempts']); ?>" min="3" max="10" />
						<p class="description"><?php esc_html_e('เกินจำนวนนี้ต้องกลับไปใส่รหัสผ่านใหม่', 'jplugin-mfa'); ?></p>
					</td>
				</tr>
			</table>

			<h2><?php esc_html_e('ทางเข้าอื่นของ WordPress', 'jplugin-mfa'); ?></h2>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><?php esc_html_e('Application Passwords', 'jplugin-mfa'); ?></th>
					<td>
						<label>
							<input type="checkbox" name="jmfa_allow_app_passwords" value="1" <?php checked(!empty($settings['allow_app_passwords'])); ?> />
						<?php esc_html_e('ยอมให้บัญชีที่ต้องใช้ MFA ใช้ Application Password ผ่าน REST API', 'jplugin-mfa'); ?>
						</label>
						<p class="description"><?php esc_html_e('ถ้าไม่ติ๊ก ผู้ใช้ที่ถูกบังคับ MFA จะใช้ Application Password ไม่ได้ (ปิดช่องทางที่ข้าม MFA ได้) — XML-RPC ถูกบล็อกเสมอเมื่อบังคับ MFA', 'jplugin-mfa'); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e('ผูกกับเครือข่าย', 'jplugin-mfa'); ?></th>
					<td>
						<label>
							<input type="checkbox" name="jmfa_bind_ip" value="1" <?php checked(!empty($settings['bind_ip'])); ?> />
							<?php esc_html_e('ยกเลิกการยืนยันถ้าที่อยู่เครือข่ายเปลี่ยนกลางคัน', 'jplugin-mfa'); ?>
						</label>
						<p class="description"><?php esc_html_e('เปิดได้ถ้าผู้ใช้ไม่ได้สลับเครือข่ายระหว่างกรอกรหัส (เช่น เปลี่ยนจาก Wi-Fi เป็น 4G)', 'jplugin-mfa'); ?></p>
					</td>
				</tr>
			</table>

			<h2><?php esc_html_e('ข้อมูลและการเก็บรักษา', 'jplugin-mfa'); ?></h2>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><label for="jmfa_log_retention"><?php esc_html_e('เก็บบันทึกเหตุการณ์ (วัน)', 'jplugin-mfa'); ?></label></th>
					<td>
						<input type="number" class="small-text" id="jmfa_log_retention" name="jmfa_log_retention"
							value="<?php echo esc_attr((int) $settings['log_retention']); ?>" min="7" max="3650" />
						<p class="description"><?php esc_html_e('เก็บเฉพาะ hash ของ IP และ User-Agent ไม่เก็บค่าจริง · ระบบลบรายการที่เก่ากว่านี้ให้อัตโนมัติทุกวัน และตรวจซ้ำทุก 6 ชั่วโมง', 'jplugin-mfa'); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e('ตอนถอนการติดตั้ง', 'jplugin-mfa'); ?></th>
					<td>
						<label>
							<input type="checkbox" name="jmfa_purge_on_uninstall" value="1" <?php checked(!empty($settings['purge_on_uninstall'])); ?> />
							<?php esc_html_e('ลบตารางและการตั้งค่าทั้งหมดเมื่อถอนปลั๊กอิน', 'jplugin-mfa'); ?>
						</label>
						<p class="description"><?php esc_html_e('ถ้าไม่ติ๊ก ข้อมูลจะถูกเก็บไว้ การปิดปลั๊กอินไม่ลบข้อมูลใด ๆ ทั้งสิ้น', 'jplugin-mfa'); ?></p>
					</td>
				</tr>
			</table>

			<?php submit_button(__('บันทึกการตั้งค่า', 'jplugin-mfa')); ?>
		</form>

		<hr />
		<h2><?php esc_html_e('ทางออกฉุกเฉิน', 'jplugin-mfa'); ?></h2>
		<p><?php esc_html_e('ถ้าเข้าเว็บไม่ได้เพราะมือถือหายและไม่มีรหัสสำรอง ให้ใส่บรรทัดนี้ใน wp-config.php ชั่วคราว:', 'jplugin-mfa'); ?></p>
		<pre><code>define( 'JMFA_DISABLE', true );</code></pre>
		<p><?php esc_html_e('หรือใช้ WP-CLI:', 'jplugin-mfa'); ?></p>
		<pre><code>wp jmfa reset &lt;username&gt;</code></pre>
		<p class="description"><?php esc_html_e('การปิดปลั๊กอินจะหยุดการบังคับ MFA ทันที และไม่ลบข้อมูลใด ๆ — เปิดกลับมาแล้วใช้ต่อได้เหมือนเดิม', 'jplugin-mfa'); ?></p>
		<?php
	}

	/* ---------------------------------------------------------------------
	 * Tab: my security
	 * ------------------------------------------------------------------ */

	private static function render_me() {
		$user_id = get_current_user_id();
		$user    = get_userdata($user_id);

		if (!$user) {
			return;
		}

		$enabled = JMFA_Store::is_enabled($user_id);
		$setup   = JMFA_Enroll::admin_setup($user_id);
		$confirm = isset($_GET['step']) && 'confirm' === sanitize_key(wp_unslash($_GET['step'])) && false !== $setup;
		$codes   = array();

		$nonce = $_GET['codes'] ?? '';
		if (is_string($nonce) && wp_verify_nonce(sanitize_text_field(wp_unslash($nonce)), 'jmfa_show_codes')) {
			$key = self::codes_key($user_id);
			$stored = '' === $key ? false : get_transient($key);

			if ($stored) {
				$plain = JMFA_Crypto::decrypt($stored);

				if (is_string($plain)) {
					$decoded = json_decode($plain, true);

					if (is_array($decoded)) {
						$codes = $decoded;
					}
				}

				delete_transient($key);
			}
		}
		?>
		<h2><?php esc_html_e('ความปลอดภัยของฉัน', 'jplugin-mfa'); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e('สถานะ', 'jplugin-mfa'); ?></th>
				<td>
					<?php if ($enabled) : ?>
						<span class="jmfa-badge jmfa-badge-on"><?php esc_html_e('เปิดใช้งาน', 'jplugin-mfa'); ?></span>
						<?php
						echo esc_html(
							sprintf(
								/* translators: %d: remaining codes */
								__('· รหัสสำรองเหลือ %d รหัส', 'jplugin-mfa'),
								JMFA_Store::recovery_remaining($user_id)
							)
						);
						?>
					<?php else : ?>
						<span class="jmfa-badge jmfa-badge-off"><?php esc_html_e('ยังไม่ตั้งค่า', 'jplugin-mfa'); ?></span>
					<?php endif; ?>
				</td>
			</tr>
		</table>
		<?php
		if ($codes) {
			?>
			<div class="notice notice-success">
				<p><strong><?php esc_html_e('รหัสสำรองชุดใหม่ — บันทึกไว้ตอนนี้', 'jplugin-mfa'); ?></strong></p>
				<ul class="jmfa-codes">
					<?php foreach ($codes as $code) : ?>
						<li><code><?php echo esc_html($code); ?></code></li>
					<?php endforeach; ?>
				</ul>
				<p>
					<button type="button" class="button jmfa-copy" data-jmfa-copy="<?php echo esc_attr(implode("\n", $codes)); ?>">
						<?php esc_html_e('คัดลอกทั้งหมด', 'jplugin-mfa'); ?>
					</button>
				</p>
				<p class="description"><?php esc_html_e('หน้านี้จะไม่แสดงรหัสเหล่านี้อีก', 'jplugin-mfa'); ?></p>
			</div>
			<?php
		}
		?>

		<?php if ($confirm) : ?>
			<?php $secret = $setup['secret']; $uri = JMFA_Enroll::provisioning_uri($user, $secret); ?>
			<h3><?php esc_html_e('สแกน QR แล้วยืนยัน', 'jplugin-mfa'); ?></h3>
			<div class="jmfa-qr" data-jmfa-qr="<?php echo esc_attr($uri); ?>"></div>
			<p class="jmfa-secret">
				<code><?php echo esc_html(JMFA_TOTP::format_secret($secret)); ?></code>
				<button type="button" class="button jmfa-copy" data-jmfa-copy="<?php echo esc_attr($secret); ?>">
					<?php esc_html_e('คัดลอก', 'jplugin-mfa'); ?>
				</button>
			</p>
			<form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
				<input type="hidden" name="action" value="jmfa_confirm_enroll" />
				<?php wp_nonce_field('jmfa_confirm_enroll'); ?>
				<p>
					<label for="jmfa_code"><?php esc_html_e('รหัส 6 หลักจากแอป', 'jplugin-mfa'); ?></label>
					<input type="text" class="regular-text" id="jmfa_code" name="jmfa_code" value=""
						inputmode="numeric" autocomplete="one-time-code" autofocus />
				</p>
				<?php submit_button(__('เปิดใช้งาน', 'jplugin-mfa'), 'primary', 'submit', false); ?>
			</form>
			<?php
		elseif (!$enabled) :
			?>
			<form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
				<input type="hidden" name="action" value="jmfa_start_enroll" />
				<?php wp_nonce_field('jmfa_start_enroll'); ?>
				<?php submit_button(__('เริ่มตั้งค่าการยืนยันตัวตนสองขั้น', 'jplugin-mfa'), 'primary', 'submit', false); ?>
			</form>
			<?php
		else :
			?>
			<h3><?php esc_html_e('สร้างรหัสสำรองชุดใหม่', 'jplugin-mfa'); ?></h3>
			<form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" class="jmfa-inline-form">
				<input type="hidden" name="action" value="jmfa_regen" />
				<?php wp_nonce_field('jmfa_regen'); ?>
				<input type="text" name="jmfa_code" value="" placeholder="<?php esc_attr_e('รหัส 6 หลัก หรือรหัสสำรอง', 'jplugin-mfa'); ?>"
					inputmode="numeric" autocomplete="one-time-code" />
				<?php submit_button(__('สร้างชุดใหม่', 'jplugin-mfa'), 'secondary', 'submit', false); ?>
			</form>

			<h3><?php esc_html_e('ปิดการยืนยันตัวตนสองขั้น', 'jplugin-mfa'); ?></h3>
			<form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" class="jmfa-inline-form">
				<input type="hidden" name="action" value="jmfa_disable" />
				<?php wp_nonce_field('jmfa_disable'); ?>
				<input type="text" name="jmfa_code" value="" placeholder="<?php esc_attr_e('รหัส 6 หลัก หรือรหัสสำรอง', 'jplugin-mfa'); ?>"
					inputmode="numeric" autocomplete="one-time-code" />
				<?php submit_button(__('ปิด MFA', 'jplugin-mfa'), 'delete', 'submit', false); ?>
			</form>
			<p class="description"><?php esc_html_e('ต้องยืนยันด้วยรหัสปัจจุบัน · เซสชันอื่นของคุณจะถูกตัดออก แต่เซสชันนี้ยังอยู่', 'jplugin-mfa'); ?></p>
			<?php
		endif;
	}

	/* ---------------------------------------------------------------------
	 * Tab: users
	 * ------------------------------------------------------------------ */

	private static function render_users() {
		$enabled_ids = JMFA_Store::enabled_user_ids();

		$role_ids = get_users(
			array(
				'role__in' => (array) JMFA_Policy::get('roles', array('administrator')),
				'fields'   => 'ID',
			)
		);

		$ids = array_unique(array_map('intval', array_merge((array) $enabled_ids, (array) $role_ids)));
		sort($ids);
		?>
		<h2><?php esc_html_e('ผู้ใช้ในขอบเขต', 'jplugin-mfa'); ?></h2>
		<p class="description">
			<?php esc_html_e('รายชื่อนี้คือผู้ใช้ที่มี MFA เปิดอยู่ หรืออยู่ในบทบาทที่ถูกบังคับในโหมด "บังคับ"', 'jplugin-mfa'); ?>
		</p>
		<table class="wp-list-table widefat fixed striped">
			<thead>
				<tr>
					<th><?php esc_html_e('ผู้ใช้', 'jplugin-mfa'); ?></th>
					<th><?php esc_html_e('บทบาท', 'jplugin-mfa'); ?></th>
					<th><?php esc_html_e('สถานะ MFA', 'jplugin-mfa'); ?></th>
					<th><?php esc_html_e('การกระทำ', 'jplugin-mfa'); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php if (!$ids) : ?>
				<tr><td colspan="4"><?php esc_html_e('ยังไม่มีผู้ใช้ในขอบเขต', 'jplugin-mfa'); ?></td></tr>
			<?php endif; ?>
			<?php foreach ($ids as $id) : ?>
				<?php
				$user = get_userdata($id);

				if (!$user) {
					continue;
				}

				$is_on = JMFA_Store::is_enabled($id);
			$can_manage = self::can_manage_user($id);
				?>
				<tr>
					<td>
						<strong><?php echo esc_html($user->user_login); ?></strong><br />
						<span class="description"><?php echo esc_html($user->user_email); ?></span>
					</td>
					<td><?php echo esc_html(self::role_labels($user)); ?></td>
					<td>
						<?php if ($is_on) : ?>
							<span class="jmfa-badge jmfa-badge-on"><?php esc_html_e('เปิดใช้งาน', 'jplugin-mfa'); ?></span>
						<?php else : ?>
							<span class="jmfa-badge jmfa-badge-off"><?php esc_html_e('ยังไม่ตั้งค่า', 'jplugin-mfa'); ?></span>
						<?php endif; ?>
					</td>
					<td>
						<?php if ($can_manage && $is_on && $id !== get_current_user_id()) : ?>
							<form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" class="jmfa-inline-form">
								<input type="hidden" name="action" value="jmfa_reset_user" />
								<input type="hidden" name="user_id" value="<?php echo esc_attr($id); ?>" />
								<?php wp_nonce_field('jmfa_reset_user_' . $id); ?>
								<button type="submit" class="button button-small"
									onclick="return confirm('<?php echo esc_js(__('รีเซ็ต MFA ของผู้ใช้นี้?', 'jplugin-mfa')); ?>');">
									<?php esc_html_e('รีเซ็ต MFA', 'jplugin-mfa'); ?>
								</button>
							</form>
						<?php endif; ?>
						<?php if ($can_manage) : ?>
							<form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" class="jmfa-inline-form">
								<input type="hidden" name="action" value="jmfa_unlock_user" />
								<input type="hidden" name="user_id" value="<?php echo esc_attr($id); ?>" />
								<?php wp_nonce_field('jmfa_unlock_user_' . $id); ?>
								<button type="submit" class="button button-small">
									<?php esc_html_e('ล้างที่ค้างอยู่', 'jplugin-mfa'); ?>
								</button>
							</form>
						<?php endif; ?>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
		<?php
	}

	/* ---------------------------------------------------------------------
	 * Tab: log
	 * ------------------------------------------------------------------ */

	private static function render_log() {
		$rows     = JMFA_Audit::recent(100);
		$retained = (int) JMFA_Policy::get('log_retention', 90);
		?>
		<h2><?php esc_html_e('บันทึกเหตุการณ์ล่าสุด', 'jplugin-mfa'); ?></h2>
		<p class="description">
			<?php
			echo esc_html(
				sprintf(
					/* translators: %d: retention in days */
					__('เก็บเฉพาะ hash ของ IP และ User-Agent · ลบอัตโนมัติเมื่อเกิน %d วัน', 'jplugin-mfa'),
					$retained
				)
			);
			?>
		</p>

		<form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" class="jmfa-inline-form jmfa-export">
			<input type="hidden" name="action" value="jmfa_export_log" />
			<?php wp_nonce_field('jmfa_export_log'); ?>
			<select name="jmfa_days" id="jmfa_days">
				<option value="0"><?php esc_html_e('ทั้งหมดที่เก็บไว้', 'jplugin-mfa'); ?></option>
				<option value="7"><?php esc_html_e('7 วันล่าสุด', 'jplugin-mfa'); ?></option>
				<option value="30"><?php esc_html_e('30 วันล่าสุด', 'jplugin-mfa'); ?></option>
				<option value="90"><?php esc_html_e('90 วันล่าสุด', 'jplugin-mfa'); ?></option>
			</select>
			<?php submit_button(__('ส่งออกรายงาน CSV', 'jplugin-mfa'), 'secondary', 'submit', false); ?>
		</form>

		<table class="wp-list-table widefat fixed striped jmfa-log">
			<thead>
				<tr>
					<th><?php esc_html_e('เวลา', 'jplugin-mfa'); ?></th>
					<th><?php esc_html_e('ผู้ใช้', 'jplugin-mfa'); ?></th>
					<th><?php esc_html_e('เหตุการณ์', 'jplugin-mfa'); ?></th>
					<th><?php esc_html_e('IP (hash)', 'jplugin-mfa'); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php if (!$rows) : ?>
				<tr><td colspan="4"><?php esc_html_e('ยังไม่มีเหตุการณ์', 'jplugin-mfa'); ?></td></tr>
			<?php endif; ?>
			<?php foreach ($rows as $row) : ?>
				<?php $log_user = (int) $row->user_id ? get_userdata((int) $row->user_id) : null; ?>
				<tr>
					<td><?php echo esc_html(get_date_from_gmt($row->created_at, 'Y-m-d H:i:s')); ?></td>
					<td><?php echo $log_user ? esc_html($log_user->user_login) : '—'; ?></td>
					<td>
						<?php echo esc_html(JMFA_Audit::label($row->event)); ?><br />
						<code><?php echo esc_html($row->event); ?></code>
					</td>
					<td><code><?php echo esc_html(substr((string) $row->ip_hash, 0, 12)); ?>…</code></td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
		<?php
	}

	/* ---------------------------------------------------------------------
	 * Handlers
	 * ------------------------------------------------------------------ */

	public static function handle_save_settings() {
		if (!current_user_can('manage_options')) {
			wp_die(esc_html__('ไม่มีสิทธิ์', 'jplugin-mfa'));
		}

		check_admin_referer('jmfa_save_settings');

		$settings = JMFA_Policy::all();

		$mode = isset($_POST['jmfa_mode']) ? sanitize_key(wp_unslash($_POST['jmfa_mode'])) : 'off';
		if (!in_array($mode, array('off', 'optional', 'required'), true)) {
			$mode = 'off';
		}
		$settings['mode'] = $mode;

		$submitted = isset($_POST['jmfa_roles']) ? (array) wp_unslash($_POST['jmfa_roles']) : array();
		$valid     = array_keys(wp_roles()->roles);
		$roles     = array_values(array_intersect(array_map('sanitize_key', $submitted), $valid));

		$settings['roles'] = $roles ? $roles : array('administrator');

		$settings['window']              = min(5, max(0, isset($_POST['jmfa_window']) ? (int) $_POST['jmfa_window'] : 1));
		$settings['max_attempts']        = min(10, max(3, isset($_POST['jmfa_max_attempts']) ? (int) $_POST['jmfa_max_attempts'] : 5));
		$settings['log_retention']       = min(3650, max(7, isset($_POST['jmfa_log_retention']) ? (int) $_POST['jmfa_log_retention'] : 90));
		$settings['allow_app_passwords'] = !empty($_POST['jmfa_allow_app_passwords']);
		$settings['bind_ip']             = !empty($_POST['jmfa_bind_ip']);
		$settings['purge_on_uninstall']  = !empty($_POST['jmfa_purge_on_uninstall']);
		$settings['issuer']              = isset($_POST['jmfa_issuer']) ? sanitize_text_field(wp_unslash($_POST['jmfa_issuer'])) : '';

		update_option(JMFA_Policy::OPTION, $settings);
		JMFA_Audit::log('settings_saved', get_current_user_id(), array('mode' => $settings['mode']));

		self::redirect('settings', 'saved');
	}

	public static function handle_start_enroll() {
		self::require_self_access(true);
		check_admin_referer('jmfa_start_enroll');

		$user_id = get_current_user_id();

		if (!JMFA_Enroll::start($user_id)) {
			self::redirect('me', 'error');
		}

		self::redirect('me', '', array('step' => 'confirm'));
	}

	public static function handle_confirm_enroll() {
		self::require_self_access(true);
		check_admin_referer('jmfa_confirm_enroll');

		$user_id = get_current_user_id();
		$setup   = JMFA_Enroll::admin_setup($user_id);

		if (!$setup || !self::allow_code_attempt($user_id)) {
			self::redirect('me', 'error');
		}

		$result = JMFA_Enroll::confirm($user_id, self::submitted_code(), $setup['generation'], $setup['secret']);

		if (is_wp_error($result)) {
			self::redirect('me', 'code_error', array('step' => 'confirm'));
		}

		JMFA_Enroll::finish_admin_setup($user_id);
		self::show_codes($user_id, $result, 'enrolled');
	}

	public static function handle_regen() {
		self::require_self_access(true);
		check_admin_referer('jmfa_regen');

		$user_id    = get_current_user_id();
		$generation = self::verify_current_code($user_id, self::submitted_code());

		if (false === $generation) {
			self::redirect('me', 'code_error');
		}

		$codes = JMFA_Store::generate_recovery_codes();
		if (!JMFA_Store::store_recovery_codes($user_id, $codes, $generation)) {
			self::redirect('me', 'error');
		}

		JMFA_Audit::log('recovery_regenerated', $user_id);
		self::show_codes($user_id, $codes, 'regen');
	}

	public static function handle_disable() {
		self::require_self_access(true);
		check_admin_referer('jmfa_disable');

		$user_id    = get_current_user_id();
		$generation = self::verify_current_code($user_id, self::submitted_code());

		if (false === $generation) {
			self::redirect('me', 'code_error');
		}

		if (!JMFA_Enroll::disable($user_id, true, $generation)) {
			self::redirect('me', 'error');
		}

		self::redirect('me', 'disabled');
	}

	public static function handle_reset_user() {
		$target = self::posted_user_id();
		if (!self::can_manage_user($target) || $target === get_current_user_id()) {
			wp_die(esc_html__('ไม่มีสิทธิ์', 'jplugin-mfa'));
		}

		check_admin_referer('jmfa_reset_user_' . $target);

		if (!get_userdata($target) || !JMFA_Store::disable($target)) {
			self::redirect('users', 'error');
		}

		JMFA_Audit::log('admin_reset', $target, array('by' => get_current_user_id()));
		JMFA_Enroll::destroy_sessions($target);

		self::redirect('users', 'reset');
	}

	public static function handle_unlock_user() {
		$target = self::posted_user_id();
		if (!self::can_manage_user($target)) {
			wp_die(esc_html__('ไม่มีสิทธิ์', 'jplugin-mfa'));
		}

		check_admin_referer('jmfa_unlock_user_' . $target);

		JMFA_Store::delete_pending_for_user($target);
		JMFA_Audit::log('admin_unlock', $target, array('by' => get_current_user_id()));

		self::redirect('users', 'unlocked');
	}

	/**
	 * Stream the audit log as a CSV report.
	 *
	 * Generated on the fly, never written to disk, and it only contains data
	 * this plugin wrote itself (client identifiers are already hashed).
	 */
	public static function handle_export_log() {
		if (!current_user_can('manage_options')) {
			wp_die(esc_html__('ไม่มีสิทธิ์', 'jplugin-mfa'));
		}

		check_admin_referer('jmfa_export_log');

		$days = isset($_POST['jmfa_days']) ? (int) $_POST['jmfa_days'] : 0;

		if (!in_array($days, array(0, 7, 30, 90, 365), true)) {
			$days = 0;
		}

		$rows = JMFA_Audit::export($days);

		JMFA_Audit::log('log_exported', get_current_user_id(), array('days' => $days, 'rows' => count($rows)));

		nocache_headers();
		header('Content-Type: text/csv; charset=utf-8');
		header('Content-Disposition: attachment; filename="jplugin-mfa-audit-' . gmdate('Ymd-His') . '.csv"');
		header('X-Content-Type-Options: nosniff');

		$output = fopen('php://output', 'w');

		if (false === $output) {
			exit;
		}

		// Byte order mark so Excel reads Thai text as UTF-8.
		fwrite($output, "\xEF\xBB\xBF");

		fputcsv(
			$output,
			array(
				__('เวลา (เวลาท้องถิ่น)', 'jplugin-mfa'),
				__('ผู้ใช้', 'jplugin-mfa'),
				__('รหัสเหตุการณ์', 'jplugin-mfa'),
				__('ความหมาย', 'jplugin-mfa'),
				__('IP (hash)', 'jplugin-mfa'),
				__('User-Agent (hash)', 'jplugin-mfa'),
				__('รายละเอียด', 'jplugin-mfa'),
			),
			',',
			'"',
			''
		);

		foreach ($rows as $row) {
			fputcsv(
				$output,
				array_map(
					array(__CLASS__, 'csv_cell'),
					array(
						get_date_from_gmt($row->created_at, 'Y-m-d H:i:s'),
						(string) $row->user_login,
						(string) $row->event,
						JMFA_Audit::label($row->event),
						(string) $row->ip_hash,
						(string) $row->ua_hash,
						(string) $row->context,
					)
				),
				',',
				'"',
				''
			);
		}

		fclose($output);
		exit;
	}

	private static function require_self_access($post = false) {
		if (!get_current_user_id() || !current_user_can('read') || ($post && 'POST' !== ($_SERVER['REQUEST_METHOD'] ?? ''))) {
			wp_die(esc_html__('ไม่มีสิทธิ์', 'jplugin-mfa'));
		}
	}

	private static function posted_user_id() {
		$id = $_POST['user_id'] ?? '';

		return is_string($id) && ctype_digit($id) ? (int) $id : 0;
	}

	private static function can_manage_user($user_id) {
		return $user_id > 0 && current_user_can('manage_options') && current_user_can('edit_user', $user_id)
			&& (!is_multisite() || is_user_member_of_blog($user_id));
	}

	private static function submitted_code() {
		$code = $_POST['jmfa_code'] ?? '';

		return is_string($code) ? sanitize_text_field(wp_unslash($code)) : '';
	}

	private static function allow_code_attempt($user_id) {
		return JMFA_Rate_Limit::allow('manage|' . (int) $user_id, 10, 5 * MINUTE_IN_SECONDS);
	}

	private static function codes_key($user_id) {
		$token = wp_get_session_token();

		return '' === $token ? '' : 'jmfa_admin_codes_' . (int) $user_id . '_' . hash('sha256', $token);
	}

	private static function show_codes($user_id, array $codes, $message) {
		$key    = self::codes_key($user_id);
		$sealed = JMFA_Crypto::encrypt(wp_json_encode($codes));

		if ('' === $key || false === $sealed || !set_transient($key, $sealed, 15 * MINUTE_IN_SECONDS)) {
			self::redirect('me', 'codes_missing');
		}

		self::redirect('me', $message, array('codes' => wp_create_nonce('jmfa_show_codes')));
	}

	/**
	 * Neutralise spreadsheet formulas in a CSV cell.
	 *
	 * @param mixed $value Cell value.
	 * @return string
	 */
	public static function csv_cell($value) {
		$value = (string) $value;

		if ('' === $value) {
			return $value;
		}

		if (in_array($value[0], array('=', '+', '-', '@', "\t", "\r"), true)) {
			return "'" . $value;
		}

		return $value;
	}

	/* ---------------------------------------------------------------------
	 * Notices and helpers
	 * ------------------------------------------------------------------ */

	public static function notices() {
		$screen = function_exists('get_current_screen') ? get_current_screen() : null;

		if (!$screen) {
			return;
		}

		if (!in_array($screen->id, array('dashboard', 'toplevel_page_' . self::SLUG, 'profile', 'user-edit'), true)) {
			return;
		}

		if (JMFA_Policy::is_disabled()) {
			echo '<div class="notice notice-warning"><p>';
			esc_html_e('jPlugin-MFA: ระบบถูกปิดด้วยค่า JMFA_DISABLE ใน wp-config.php', 'jplugin-mfa');
			echo '</p></div>';

			return;
		}

		$user = get_userdata(get_current_user_id());

		if (!$user || !JMFA_Policy::requires_gate($user) || JMFA_Store::is_enabled($user->ID)) {
			return;
		}

		printf(
			'<div class="notice notice-warning"><p>%1$s <a href="%2$s">%3$s</a></p></div>',
			esc_html__('jPlugin-MFA: บัญชีนี้ถูกกำหนดให้ใช้การยืนยันตัวตนสองขั้นแต่ยังไม่ได้ตั้งค่า', 'jplugin-mfa'),
			esc_url(self::tab_url('me')),
			esc_html__('ตั้งค่าเดี๋ยวนี้', 'jplugin-mfa')
		);
	}

	/**
	 * @param int    $user_id User ID.
	 * @param string $code    Six digit code or recovery code.
	 * @return string|false Generation of the credential that accepted the code.
	 */
	private static function verify_current_code($user_id, $code) {
		if (!self::allow_code_attempt($user_id)) {
			return false;
		}

		$row = JMFA_Store::credential($user_id, true);
		if (!$row || 'enabled' !== $row->state) {
			return false;
		}

		if (JMFA_Store::consume_totp($user_id, $code, $row->generation)) {
			return $row->generation;
		}

		if (JMFA_Store::consume_recovery_code($user_id, $code, $row->generation)) {
			JMFA_Audit::log('recovery_used', $user_id);

			return $row->generation;
		}

		JMFA_Audit::log('verify_fail', $user_id, array('where' => 'admin'));

		return false;
	}

	/**
	 * @param WP_User $user User object.
	 * @return string Comma separated, translated role names.
	 */
	private static function role_labels($user) {
		$roles = wp_roles();
		$names = array();

		foreach ((array) $user->roles as $slug) {
			if (isset($roles->roles[ $slug ]['name'])) {
				$names[] = translate_user_role($roles->roles[ $slug ]['name']);
			}
		}

		return implode(', ', $names);
	}

	/**
	 * @param string $tab Tab slug.
	 * @return string
	 */
	public static function tab_url($tab) {
		if ('me' === $tab && !current_user_can('manage_options')) {
			return add_query_arg('page', self::SELF_SLUG, admin_url('profile.php'));
		}

		return add_query_arg(
			array(
				'page' => self::SLUG,
				'tab'  => $tab,
			),
			admin_url('admin.php')
		);
	}

	/**
	 * @param string $tab     Tab slug.
	 * @param string $message Message code.
	 * @param array  $extra   Extra query args.
	 */
	private static function redirect($tab, $message = '', array $extra = array()) {
		if ('' !== $message) {
			$extra['jmfa_msg'] = $message;
		}

		wp_safe_redirect(add_query_arg($extra, self::tab_url($tab)));
		exit;
	}
}
