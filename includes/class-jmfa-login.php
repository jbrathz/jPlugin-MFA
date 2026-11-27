<?php
/**
 * The login gate.
 *
 * Hooks only the native WordPress login: the authenticate filter plus the
 * login_form_* action that wp-login.php already supports for custom actions.
 *
 * @package jPlugin-MFA
 */

if (!defined('ABSPATH')) {
	exit;
}

class JMFA_Login {

	const COOKIE = 'jmfa_pending';

	/**
	 * Register hooks. Called on every request, including wp-login.php.
	 */
	public static function init() {
		add_filter('authenticate', array(__CLASS__, 'gate'), 30, 3);
		add_action('login_init', array(__CLASS__, 'on_login_init'));
		add_action('login_form_jmfa', array(__CLASS__, 'route'));
		add_action('login_enqueue_scripts', array(__CLASS__, 'enqueue'));
		add_action('wp_logout', array(__CLASS__, 'on_logout'));
		add_action('clear_auth_cookie', array(__CLASS__, 'clear_cookie'));
	}

	/* ---------------------------------------------------------------------
	 * Step 1: password accepted, start the second step
	 * ------------------------------------------------------------------ */

	/**
	 * @param WP_User|WP_Error $user     Result of the earlier authenticate callbacks.
	 * @param string           $username Submitted login.
	 * @param string           $password Submitted password.
	 * @return WP_User|WP_Error
	 */
	public static function gate($user, $username, $password) {
		if (!($user instanceof WP_User)) {
			return $user;
		}

		if (!JMFA_Policy::requires_gate($user)) {
			return $user;
		}

		if (!self::is_core_login_request()) {
			if (JMFA_Policy::get('allow_app_passwords') && self::is_application_password_request()) {
				JMFA_Audit::log('bypass_app_password', $user->ID);

				return $user;
			}

			JMFA_Audit::log('blocked_non_web', $user->ID);

			return new WP_Error(
				'jmfa_required_elsewhere',
				__('บัญชีนี้ต้องยืนยันตัวตนสองขั้น กรุณาเข้าสู่ระบบผ่านหน้า wp-login.php', 'jplugin-mfa')
			);
		}

		/*
		 * Throttle per account and client address, not per address alone:
		 * behind a reverse proxy or an office NAT every admin shares one
		 * address, and a shared bucket would lock everybody out at once.
		 */
		$bucket = 'pending|' . strtolower((string) $username) . '|' . JMFA_Audit::client_ip();

		if (!JMFA_Rate_Limit::allow($bucket, 20, 10 * MINUTE_IN_SECONDS)) {
			JMFA_Audit::log('throttled', $user->ID);

			return new WP_Error('jmfa_throttled', __('คำขอเข้าสู่ระบบมากเกินไป กรุณารอสักครู่แล้วลองใหม่', 'jplugin-mfa'));
		}

		$stage = JMFA_Store::is_enabled($user->ID) ? 'verify' : 'enroll';

		$redirect = admin_url();
		if (isset($_REQUEST['redirect_to'])) {
			$candidate = wp_validate_redirect(wp_unslash($_REQUEST['redirect_to']), '');
			if ('' !== $candidate) {
				$redirect = $candidate;
			}
		}

		if (!empty($_REQUEST['interim-login'])) {
			$redirect = add_query_arg('interim-login', 1, $redirect);
		}

		$pending = JMFA_Store::create_pending($user->ID, $stage, !empty($_POST['rememberme']), $redirect);

		if (!$pending || empty($pending['token'])) {
			return new WP_Error('jmfa_state', __('เริ่มการยืนยันตัวตนไม่สำเร็จ กรุณาลองเข้าสู่ระบบใหม่', 'jplugin-mfa'));
		}

		self::set_cookie($pending['token']);
		JMFA_Audit::log('password_ok', $user->ID, array('stage' => $stage));

		$url = add_query_arg('action', 'jmfa', wp_login_url());

		if (!wp_safe_redirect($url)) {
			JMFA_Store::delete_pending((int) $pending['id']);
			self::clear_cookie();

			return new WP_Error('jmfa_redirect', __('เปลี่ยนหน้าไม่สำเร็จ กรุณาลองใหม่', 'jplugin-mfa'));
		}

		exit;
	}

	/* ---------------------------------------------------------------------
	 * Step 2: render and process
	 * ------------------------------------------------------------------ */

	/**
	 * Fires for wp-login.php?action=jmfa before any output.
	 */
	public static function route() {
		if (JMFA_Policy::is_disabled()) {
			self::render_message(
				__('ปิดการยืนยันตัวตนสองขั้น', 'jplugin-mfa'),
				__('ระบบปิดการยืนยันตัวตนสองขั้นอยู่ กรุณาเข้าสู่ระบบใหม่', 'jplugin-mfa'),
				true
			);

			return;
		}

		$pending = self::current_pending();

		if (!$pending) {
			self::render_message(
				__('เซสชันหมดอายุ', 'jplugin-mfa'),
				__('การยืนยันตัวตนหมดอายุหรือถูกยกเลิก กรุณาเข้าสู่ระบบใหม่', 'jplugin-mfa'),
				true
			);

			return;
		}

		$user = get_user_by('id', (int) $pending->user_id);

		if (!$user) {
			self::discard_pending($pending);
			self::render_message(__('ไม่พบบัญชีผู้ใช้', 'jplugin-mfa'), __('กรุณาเข้าสู่ระบบใหม่', 'jplugin-mfa'), true);

			return;
		}

		if (JMFA_Policy::get('bind_ip') && !hash_equals((string) $pending->ip_hash, JMFA_Audit::ip_hash())) {
			self::discard_pending($pending);
			JMFA_Audit::log('ip_mismatch', $user->ID);
			self::render_message(
				__('ตรวจพบการเปลี่ยนแปลงเครือข่าย', 'jplugin-mfa'),
				__('ที่อยู่เครือข่ายเปลี่ยนระหว่างการยืนยันตัวตน กรุณาเข้าสู่ระบบใหม่', 'jplugin-mfa'),
				true
			);

			return;
		}

		if ('verify' === $pending->stage && JMFA_Store::is_enabled($user->ID) && false === JMFA_Store::secret($user->ID)) {
			self::discard_pending($pending);
			JMFA_Audit::log('secret_unreadable', $user->ID);
			self::render_message(
				__('ข้อมูลการยืนยันตัวตนเสียหาย', 'jplugin-mfa'),
				__('อ่านค่าความลับของบัญชีนี้ไม่ได้ (มักเกิดจากการเปลี่ยน AUTH_KEY) กรุณาให้ผู้ดูแลระบบรีเซ็ต MFA ให้บัญชีนี้', 'jplugin-mfa'),
				true
			);

			return;
		}

		if (isset($_SERVER['REQUEST_METHOD']) && 'POST' === strtoupper((string) $_SERVER['REQUEST_METHOD'])) {
			self::handle_post($pending, $user);

			return;
		}

		self::render_stage($pending, $user);
	}

	/**
	 * @param object  $pending Pending row.
	 * @param WP_User $user    User object.
	 */
	private static function handle_post($pending, $user) {
		$nonce = isset($_POST['_wpnonce']) ? sanitize_text_field(wp_unslash($_POST['_wpnonce'])) : '';

		if (!wp_verify_nonce($nonce, 'jmfa_step_' . (int) $pending->id)) {
			self::render_stage($pending, $user, __('เซสชันไม่ถูกต้อง กรุณาลองใหม่', 'jplugin-mfa'));

			return;
		}

		$action = isset($_POST['jmfa_action']) ? sanitize_key(wp_unslash($_POST['jmfa_action'])) : 'code';

		if ('finish' === $action) {
			if ('codes' !== $pending->stage) {
				self::render_stage($pending, $user, __('ขั้นตอนไม่ถูกต้อง', 'jplugin-mfa'));

				return;
			}

			self::complete_login($pending, $user, 'login_ok');

			return;
		}

		if ('recovery' === $action) {
			$code = isset($_POST['jmfa_recovery']) ? sanitize_text_field(wp_unslash($_POST['jmfa_recovery'])) : '';

			if (JMFA_Store::consume_recovery_code($user->ID, $code)) {
				JMFA_Audit::log('recovery_used', $user->ID);
				self::complete_login($pending, $user, 'login_ok_recovery');

				return;
			}

			self::register_failure($pending, $user, __('รหัสสำรองไม่ถูกต้องหรือถูกใช้ไปแล้ว', 'jplugin-mfa'));

			return;
		}

		$code = isset($_POST['jmfa_code']) ? sanitize_text_field(wp_unslash($_POST['jmfa_code'])) : '';

		if ('enroll' === $pending->stage) {
			$result = JMFA_Enroll::confirm($user->ID, $code);

			if (is_wp_error($result)) {
				self::register_failure($pending, $user, $result->get_error_message());

				return;
			}

			JMFA_Store::stash_codes((int) $pending->id, $result);
			JMFA_Store::set_stage((int) $pending->id, 'codes');
			JMFA_Store::touch_pending((int) $pending->id, 15 * MINUTE_IN_SECONDS);

			$fresh = JMFA_Store::get_pending_by_id((int) $pending->id);

			self::render_stage($fresh ? $fresh : $pending, $user);

			return;
		}

		if ('codes' === $pending->stage) {
			self::render_stage($pending, $user);

			return;
		}

		$secret = JMFA_Store::secret($user->ID);

		if (false === $secret) {
			self::render_stage($pending, $user, __('อ่านข้อมูลการยืนยันตัวตนไม่ได้ กรุณาให้ผู้ดูแลระบบรีเซ็ต', 'jplugin-mfa'));

			return;
		}

		$step = JMFA_TOTP::verify($secret, $code, (int) JMFA_Policy::get('window', 1), JMFA_Store::last_step($user->ID));

		if (false === $step) {
			self::register_failure($pending, $user, __('รหัสไม่ถูกต้อง หรือเวลาในอุปกรณ์ไม่ตรงกับเซิร์ฟเวอร์', 'jplugin-mfa'));

			return;
		}

		JMFA_Store::set_last_step($user->ID, $step);
		JMFA_Audit::log('verify_ok', $user->ID);
		self::complete_login($pending, $user, 'login_ok');
	}

	/**
	 * Count a failed attempt and lock the pending login when the limit is hit.
	 *
	 * @param object  $pending Pending row.
	 * @param WP_User $user    User object.
	 * @param string  $message Message to show.
	 */
	private static function register_failure($pending, $user, $message) {
		$attempts = JMFA_Store::bump_attempts((int) $pending->id);
		$max      = max(3, (int) JMFA_Policy::get('max_attempts', 5));

		JMFA_Audit::log('verify_fail', $user->ID, array('attempts' => $attempts));

		if ($attempts >= $max) {
			self::discard_pending($pending);
			JMFA_Audit::log('locked', $user->ID);
			self::render_message(
				__('พยายามมากเกินไป', 'jplugin-mfa'),
				__('กรอกรหัสผิดหลายครั้งเกินไป กรุณาเข้าสู่ระบบใหม่ตั้งแต่ต้น', 'jplugin-mfa'),
				true
			);

			return;
		}

		self::render_stage(
			$pending,
			$user,
			$message . ' ' . sprintf(
				/* translators: %d: remaining attempts */
				__('เหลืออีก %d ครั้ง', 'jplugin-mfa'),
				$max - $attempts
			)
		);
	}

	/**
	 * Finish authentication: session cookie, wp_login action, redirect.
	 *
	 * @param object  $pending Pending row.
	 * @param WP_User $user    User object.
	 * @param string  $event   Audit event key.
	 */
	private static function complete_login($pending, $user, $event) {
		JMFA_Store::delete_pending((int) $pending->id);
		JMFA_Store::forget_codes((int) $pending->id);
		self::clear_cookie();

		$redirect = wp_validate_redirect((string) $pending->redirect_to, admin_url());

		wp_set_current_user((int) $user->ID);
		wp_set_auth_cookie((int) $user->ID, (bool) $pending->remember);

		/** This action is documented in wp-login.php. */
		do_action('wp_login', $user->user_login, $user);

		JMFA_Audit::log($event, $user->ID);

		wp_safe_redirect($redirect);
		exit;
	}

	/* ---------------------------------------------------------------------
	 * Rendering
	 * ------------------------------------------------------------------ */

	/**
	 * @param object  $pending Pending row.
	 * @param WP_User $user    User object.
	 * @param string  $error   Optional error message.
	 */
	private static function render_stage($pending, $user, $error = '') {
		switch ((string) $pending->stage) {
			case 'enroll':
				self::render_enroll($pending, $user, $error);
				break;
			case 'codes':
				self::render_codes($pending, $user);
				break;
			default:
				self::render_verify($pending, $user, $error);
		}

		exit;
	}

	/**
	 * @param object  $pending Pending row.
	 * @param WP_User $user    User object.
	 * @param string  $error   Optional error message.
	 */
	private static function render_verify($pending, $user, $error = '') {
		self::open_page(
			__('ยืนยันตัวตนสองขั้น', 'jplugin-mfa'),
			'' !== $error ? $error : ''
		);

		$remaining = JMFA_Store::recovery_remaining($user->ID);
		?>
		<form name="jmfa-code-form" id="jmfa-code-form" action="<?php echo esc_url(self::form_url()); ?>" method="post">
			<p>
				<label for="jmfa_code"><?php esc_html_e('รหัส 6 หลักจากแอป Authenticator', 'jplugin-mfa'); ?></label>
				<input type="text" name="jmfa_code" id="jmfa_code" class="input" value="" size="20"
					inputmode="numeric" autocomplete="one-time-code" autocapitalize="off" spellcheck="false" autofocus />
			</p>
			<?php wp_nonce_field('jmfa_step_' . (int) $pending->id); ?>
			<input type="hidden" name="jmfa_action" value="code" />
			<p class="submit">
				<input type="submit" class="button button-primary button-large" value="<?php esc_attr_e('ยืนยัน', 'jplugin-mfa'); ?>" />
			</p>
		</form>

		<p class="jmfa-hint">
			<?php
			echo esc_html(
				sprintf(
					/* translators: 1: user login, 2: server time */
					__('บัญชี %1$s · เวลาเซิร์ฟเวอร์ %2$s UTC', 'jplugin-mfa'),
					$user->user_login,
					gmdate('H:i:s')
				)
			);
			?>
		</p>

		<?php if ($remaining > 0) : ?>
			<details class="jmfa-details">
				<summary><?php esc_html_e('ใช้รหัสสำรองแทน', 'jplugin-mfa'); ?></summary>
				<form name="jmfa-recovery-form" action="<?php echo esc_url(self::form_url()); ?>" method="post">
					<p>
						<label for="jmfa_recovery"><?php esc_html_e('รหัสสำรอง (ใช้ได้ครั้งเดียว)', 'jplugin-mfa'); ?></label>
						<input type="text" name="jmfa_recovery" id="jmfa_recovery" class="input" value="" size="20"
							autocomplete="off" autocapitalize="characters" spellcheck="false" />
					</p>
					<?php wp_nonce_field('jmfa_step_' . (int) $pending->id); ?>
					<input type="hidden" name="jmfa_action" value="recovery" />
					<p class="submit">
						<input type="submit" class="button" value="<?php esc_attr_e('ใช้รหัสสำรอง', 'jplugin-mfa'); ?>" />
					</p>
				</form>
				<p class="jmfa-hint">
					<?php
					echo esc_html(
						sprintf(
							/* translators: %d: remaining codes */
							__('เหลือรหัสสำรองอีก %d รหัส', 'jplugin-mfa'),
							$remaining
						)
					);
					?>
				</p>
			</details>
		<?php endif; ?>

		<p id="nav">
			<a href="<?php echo esc_url(wp_login_url()); ?>"><?php esc_html_e('ยกเลิกและกลับไปหน้าเข้าสู่ระบบ', 'jplugin-mfa'); ?></a>
		</p>
		<?php
		self::close_page();
	}

	/**
	 * @param object  $pending Pending row.
	 * @param WP_User $user    User object.
	 * @param string  $error   Optional error message.
	 */
	private static function render_enroll($pending, $user, $error = '') {
		$secret = JMFA_Enroll::secret_for_user($user->ID);

		if (false === $secret) {
			self::render_message(
				__('ตั้งค่าไม่สำเร็จ', 'jplugin-mfa'),
				__('สร้างค่าความลับไม่สำเร็จ กรุณาลองใหม่', 'jplugin-mfa'),
				true
			);

			return;
		}

		$uri = JMFA_Enroll::provisioning_uri($user, $secret);

		self::open_page(
			__('ตั้งค่าการยืนยันตัวตนสองขั้น', 'jplugin-mfa'),
			'' !== $error ? $error : ''
		);
		?>
		<p class="message">
			<?php esc_html_e('สแกน QR ด้วย Google Authenticator หรือแอป TOTP อื่น ๆ แล้วกรอกรหัส 6 หลักเพื่อยืนยัน', 'jplugin-mfa'); ?>
		</p>

		<div class="jmfa-qr" data-jmfa-qr="<?php echo esc_attr($uri); ?>"></div>

		<p class="jmfa-secret">
			<label for="jmfa_secret_text"><?php esc_html_e('หรือพิมพ์ค่าความลับนี้ด้วยมือ', 'jplugin-mfa'); ?></label>
			<code id="jmfa_secret_text"><?php echo esc_html(JMFA_TOTP::format_secret($secret)); ?></code>
			<button type="button" class="button jmfa-copy" data-jmfa-copy="<?php echo esc_attr($secret); ?>">
				<?php esc_html_e('คัดลอก', 'jplugin-mfa'); ?>
			</button>
		</p>

		<form name="jmfa-enroll-form" action="<?php echo esc_url(self::form_url()); ?>" method="post">
			<p>
				<label for="jmfa_code"><?php esc_html_e('รหัส 6 หลักที่แอปแสดง', 'jplugin-mfa'); ?></label>
				<input type="text" name="jmfa_code" id="jmfa_code" class="input" value="" size="20"
					inputmode="numeric" autocomplete="one-time-code" autocapitalize="off" spellcheck="false" autofocus />
			</p>
			<?php wp_nonce_field('jmfa_step_' . (int) $pending->id); ?>
			<input type="hidden" name="jmfa_action" value="code" />
			<p class="submit">
				<input type="submit" class="button button-primary button-large" value="<?php esc_attr_e('เปิดใช้งาน', 'jplugin-mfa'); ?>" />
			</p>
		</form>

		<p class="jmfa-hint">
			<?php
			echo esc_html(
				sprintf(
					/* translators: %s: server time */
					__('เวลาเซิร์ฟเวอร์ %s UTC — ถ้าแอปขึ้นรหัสไม่ถูกต้อง ให้ตรวจเวลาของอุปกรณ์', 'jplugin-mfa'),
					gmdate('H:i:s')
				)
			);
			?>
		</p>

		<p id="nav">
			<a href="<?php echo esc_url(wp_login_url()); ?>"><?php esc_html_e('ยกเลิกและกลับไปหน้าเข้าสู่ระบบ', 'jplugin-mfa'); ?></a>
		</p>
		<?php
		self::close_page();
	}

	/**
	 * @param object  $pending Pending row.
	 * @param WP_User $user    User object.
	 */
	private static function render_codes($pending, $user) {
		$codes = JMFA_Store::take_codes((int) $pending->id);

		self::open_page(__('บันทึกรหัสสำรอง', 'jplugin-mfa'));

		if ($codes) {
			?>
			<p class="message">
				<?php esc_html_e('เก็บรหัสเหล่านี้ไว้ในที่ปลอดภัย ใช้ได้ครั้งละหนึ่งรหัสเมื่อไม่มีอุปกรณ์ และจะแสดงเพียงครั้งเดียว', 'jplugin-mfa'); ?>
			</p>
			<ul class="jmfa-codes">
				<?php foreach ($codes as $code) : ?>
					<li><code><?php echo esc_html($code); ?></code></li>
				<?php endforeach; ?>
			</ul>
			<p>
				<button type="button" class="button jmfa-copy" data-jmfa-copy="<?php echo esc_attr(implode("\n", $codes)); ?>">
					<?php esc_html_e('คัดลอกรหัสทั้งหมด', 'jplugin-mfa'); ?>
				</button>
			</p>
			<?php
		} else {
			?>
			<p class="message">
				<?php esc_html_e('รหัสสำรองถูกแสดงไปแล้ว ถ้าหายไปสามารถสร้างชุดใหม่ได้ที่หน้า jPlugin-MFA → ความปลอดภัยของฉัน', 'jplugin-mfa'); ?>
			</p>
			<?php
		}
		?>
		<form action="<?php echo esc_url(self::form_url()); ?>" method="post">
			<?php wp_nonce_field('jmfa_step_' . (int) $pending->id); ?>
			<input type="hidden" name="jmfa_action" value="finish" />
			<p class="submit">
				<input type="submit" class="button button-primary button-large" value="<?php esc_attr_e('เข้าสู่ระบบ', 'jplugin-mfa'); ?>" />
			</p>
		</form>
		<?php
		self::close_page();
	}

	/**
	 * @param string $title   Page heading.
	 * @param string $message Error message.
	 * @param bool   $is_warn Unused, kept for call-site clarity.
	 */
	private static function render_message($title, $message, $is_warn = false) {
		self::open_page($title, $message);
		?>
		<p id="nav">
			<a href="<?php echo esc_url(wp_login_url()); ?>"><?php esc_html_e('กลับไปหน้าเข้าสู่ระบบ', 'jplugin-mfa'); ?></a>
		</p>
		<?php
		self::close_page();
		exit;
	}

	/**
	 * @param string $title Page heading.
	 * @param string $error Error message.
	 */
	private static function open_page($title, $error = '') {
		if (!function_exists('login_header')) {
			wp_die(esc_html($title));
		}

		login_header($title, '', '' !== $error ? new WP_Error('jmfa_error', $error) : '');
	}

	private static function close_page() {
		if (function_exists('login_footer')) {
			login_footer();
		}
	}

	/* ---------------------------------------------------------------------
	 * Helpers
	 * ------------------------------------------------------------------ */

	/**
	 * @return string Action URL of the second step.
	 */
	private static function form_url() {
		return add_query_arg('action', 'jmfa', wp_login_url());
	}

	/**
	 * @return object|null Pending row for the current cookie.
	 */
	private static function current_pending() {
		if (empty($_COOKIE[ self::COOKIE ])) {
			return null;
		}

		return JMFA_Store::get_pending(sanitize_text_field(wp_unslash($_COOKIE[ self::COOKIE ])));
	}

	/**
	 * @param object $pending Pending row.
	 */
	private static function discard_pending($pending) {
		JMFA_Store::delete_pending((int) $pending->id);
		JMFA_Store::forget_codes((int) $pending->id);
		self::clear_cookie();
	}

	/**
	 * Only the native login form may start this flow.
	 *
	 * @return bool
	 */
	private static function is_core_login_request() {
		if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
			return false;
		}

		if (defined('REST_REQUEST') && REST_REQUEST) {
			return false;
		}

		if (defined('WP_CLI') && WP_CLI) {
			return false;
		}

		/*
		 * wp-login.php fires login_init before it calls wp_signon(), so this is
		 * the reliable signal that the request really is the native login form.
		 * $pagenow is only a secondary hint: wp-login.php does not set it.
		 */
		if (did_action('login_init') > 0) {
			return true;
		}

		$pagenow = isset($GLOBALS['pagenow']) ? (string) $GLOBALS['pagenow'] : '';

		return 'wp-login.php' === $pagenow;
	}

	/**
	 * @return bool
	 */
	private static function is_application_password_request() {
		return !empty($_SERVER['PHP_AUTH_USER']) && isset($_SERVER['PHP_AUTH_PW']);
	}

	/**
	 * @return string Cookie path that matches the WordPress install directory.
	 */
	private static function cookie_path() {
		if (defined('SITECOOKIEPATH') && SITECOOKIEPATH) {
			return SITECOOKIEPATH;
		}

		return '/';
	}

	/**
	 * @return string
	 */
	private static function cookie_domain() {
		if (defined('COOKIE_DOMAIN') && COOKIE_DOMAIN) {
			return COOKIE_DOMAIN;
		}

		return '';
	}

	/**
	 * @param string $token Raw pending token.
	 */
	private static function set_cookie($token) {
		if (headers_sent()) {
			return;
		}

		setcookie(
			self::COOKIE,
			(string) $token,
			array(
				'expires'  => time() + JMFA_Store::PENDING_TTL,
				'path'     => self::cookie_path(),
				'domain'   => self::cookie_domain(),
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);

		$_COOKIE[ self::COOKIE ] = (string) $token;
	}

	/**
	 * Remove the pending cookie.
	 */
	public static function clear_cookie() {
		unset($_COOKIE[ self::COOKIE ]);

		if (headers_sent()) {
			return;
		}

		setcookie(
			self::COOKIE,
			'',
			array(
				'expires'  => time() - 3600,
				'path'     => self::cookie_path(),
				'domain'   => self::cookie_domain(),
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);
	}

	/**
	 * Drop a stale pending login as soon as the login form is opened again.
	 */
	public static function on_login_init() {
		$action = isset($_REQUEST['action']) ? sanitize_key(wp_unslash($_REQUEST['action'])) : 'login';

		if ('' === $action) {
			$action = 'login';
		}

		if (!in_array($action, array('login', 'logout'), true)) {
			return;
		}

		if (!isset($_SERVER['REQUEST_METHOD']) || 'GET' !== strtoupper((string) $_SERVER['REQUEST_METHOD'])) {
			return;
		}

		if (empty($_COOKIE[ self::COOKIE ])) {
			return;
		}

		JMFA_Store::delete_pending_by_token(sanitize_text_field(wp_unslash($_COOKIE[ self::COOKIE ])));
		self::clear_cookie();
	}

	/**
	 * @param int $user_id User ID.
	 */
	public static function on_logout($user_id = 0) {
		self::clear_cookie();

		if ($user_id) {
			JMFA_Audit::log('logout', (int) $user_id);
		}
	}

	/**
	 * Styles and scripts for the second step only.
	 */
	public static function enqueue() {
		$action = isset($_REQUEST['action']) ? sanitize_key(wp_unslash($_REQUEST['action'])) : '';

		if ('jmfa' !== $action) {
			return;
		}

		wp_enqueue_style('jmfa-login', JMFA_URL . 'assets/css/jmfa.css', array(), JMFA_VERSION);
		// wp-login.php prints enqueued scripts in the head, not in the footer.
		wp_enqueue_script('jmfa-qr', JMFA_URL . 'assets/js/qrcode.js', array(), '1.4.4', false);
		wp_enqueue_script('jmfa-login', JMFA_URL . 'assets/js/jmfa.js', array('jmfa-qr'), JMFA_VERSION, false);
	}
}