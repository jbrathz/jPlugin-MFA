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
	private static $secure_signon = false;
	private static $remember = false;

	/**
	 * Register hooks. Called on every request, including wp-login.php.
	 */
	public static function init() {
		add_action('login_form_login', array(__CLASS__, 'on_login_form'));
		add_action('login_form_logout', array(__CLASS__, 'on_logout_form'));
		add_action('login_form_jmfa', array(__CLASS__, 'route'));
		add_action('login_enqueue_scripts', array(__CLASS__, 'enqueue'));
		add_action('wp_authenticate_application_password_errors', array(__CLASS__, 'check_application_password'), 10, 2);

		if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
			add_filter('authenticate', array(__CLASS__, 'check_xmlrpc'), PHP_INT_MAX);
		}
	}

	public static function on_login_form() {
		if ('POST' === ($_SERVER['REQUEST_METHOD'] ?? '')) {
			if (!JMFA_Policy::is_disabled() && JMFA_Policy::MODE_OFF !== JMFA_Policy::get('mode')) {
				add_filter('secure_signon_cookie', array(__CLASS__, 'prepare_signon'), PHP_INT_MAX, 2);
			}
			return;
		}

		self::cancel_pending_from_cookie();
	}

	public static function prepare_signon($secure, $credentials) {
		remove_filter('secure_signon_cookie', array(__CLASS__, 'prepare_signon'), PHP_INT_MAX);
		if ('' !== ($credentials['user_login'] ?? '') && '' !== ($credentials['user_password'] ?? '')) {
			self::$secure_signon = (bool) $secure;
			self::$remember = !empty($credentials['remember']);
			add_filter('authenticate', array(__CLASS__, 'gate'), PHP_INT_MAX);
		}

		return $secure;
	}

	public static function check_application_password($error, $user) {
		$is_rest = defined('REST_REQUEST') && REST_REQUEST;
		$is_xmlrpc = defined('XMLRPC_REQUEST') && XMLRPC_REQUEST;

		if ((!$is_rest && !$is_xmlrpc) || $error->has_errors() || !JMFA_Policy::requires_gate($user)) {
			return;
		}

		if ($is_rest && !$is_xmlrpc && JMFA_Policy::get('allow_app_passwords')) {
			JMFA_Audit::log('bypass_app_password', $user->ID);
			return;
		}

		$error->add('jmfa_required_elsewhere', self::block_non_web($user)->get_error_message());
	}

	public static function check_xmlrpc($user) {
		return JMFA_Policy::requires_gate($user) ? self::block_non_web($user) : $user;
	}

	private static function block_non_web($user) {
		JMFA_Audit::log('blocked_non_web', $user->ID);

		return new WP_Error(
			'jmfa_required_elsewhere',
			__('บัญชีนี้ต้องยืนยันตัวตนสองขั้น กรุณาเข้าสู่ระบบผ่านหน้า wp-login.php', 'jplugin-mfa')
		);
	}

	/* ---------------------------------------------------------------------
	 * Step 1: password accepted, start the second step
	 * ------------------------------------------------------------------ */

	/**
	 * @param WP_User|WP_Error $user Result of the earlier authenticate callbacks.
	 * @return WP_User|WP_Error
	 */
	public static function gate($user) {
		remove_filter('authenticate', array(__CLASS__, 'gate'), PHP_INT_MAX);
		if (!JMFA_Policy::requires_gate($user)) {
			return $user;
		}

		/*
		 * Throttle per account and client address, not per address alone:
		 * behind a reverse proxy or an office NAT every admin shares one
		 * address, and a shared bucket would lock everybody out at once.
		 */
		$bucket = 'pending|' . (int) $user->ID . '|' . JMFA_Audit::client_ip();

		if (!JMFA_Rate_Limit::allow($bucket, 20, 10 * MINUTE_IN_SECONDS)) {
			JMFA_Audit::log('throttled', $user->ID);

			return new WP_Error('jmfa_throttled', __('คำขอเข้าสู่ระบบมากเกินไป กรุณารอสักครู่แล้วลองใหม่', 'jplugin-mfa'));
		}

		$credential = JMFA_Store::credential($user->ID, true);
		// Core may have rehashed the password during authentication.
		$current_user = get_user_by('id', $user->ID);
		if (!$current_user) {
			return new WP_Error('jmfa_state', __('เริ่มการยืนยันตัวตนไม่สำเร็จ กรุณาลองเข้าสู่ระบบใหม่', 'jplugin-mfa'));
		}

		$requested  = $_REQUEST['redirect_to'] ?? '';
		$requested  = is_string($requested) && strlen($requested) <= 8192 ? wp_unslash($requested) : '';
		$redirect   = wp_validate_redirect($requested, admin_url());
		$context    = array(
			'requested'  => $requested,
			'interim'    => isset($_REQUEST['interim-login']),
			'customizer' => isset($_REQUEST['customize-login']),
			'secure'     => self::$secure_signon,
			'password'   => self::password_stamp($current_user),
		);
		$pending = $credential
			? JMFA_Store::create_pending($user->ID, $credential, self::$remember, $redirect, $context)
			: false;

		if (!$pending) {
			return new WP_Error('jmfa_state', __('เริ่มการยืนยันตัวตนไม่สำเร็จ กรุณาลองเข้าสู่ระบบใหม่', 'jplugin-mfa'));
		}

		if (!self::set_cookie($pending['token']) || !wp_safe_redirect(self::form_url())) {
			JMFA_Store::delete_pending((int) $pending['id']);
			self::clear_cookie();

			return new WP_Error('jmfa_redirect', __('เปลี่ยนหน้าไม่สำเร็จ กรุณาลองใหม่', 'jplugin-mfa'));
		}

		JMFA_Audit::log('password_ok', $user->ID, array('stage' => $pending['stage']));
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

		$credential = JMFA_Store::credential($user->ID);
		$context    = json_decode((string) ($pending->login_context ?? ''), true);
		$enrolling  = 'enroll' === $pending->stage;

		if (!$credential || '' === ($pending->generation ?? '') || $credential->generation !== $pending->generation
			|| $enrolling === ('enabled' === $credential->state)
			|| !is_string($context['password'] ?? null) || !hash_equals(self::password_stamp($user), $context['password'])
			|| !JMFA_Policy::requires_gate($user) || is_wp_error(wp_authenticate_spam_check($user))) {
			self::expire_pending($pending);
		}

		$pending->context = $context;
		$GLOBALS['interim_login'] = !empty($context['interim']);

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

		if ('verify' === $pending->stage && false === JMFA_Crypto::decrypt($credential->secret)
			&& 0 === JMFA_Store::recovery_remaining($user->ID)) {
			self::discard_pending($pending);
			JMFA_Audit::log('secret_unreadable', $user->ID);
			self::render_message(
				__('ข้อมูลการยืนยันตัวตนเสียหาย', 'jplugin-mfa'),
				__('อ่านค่าความลับของบัญชีนี้ไม่ได้ (มักเกิดจากการเปลี่ยน AUTH_KEY) กรุณาให้ผู้ดูแลระบบรีเซ็ต MFA ให้บัญชีนี้', 'jplugin-mfa'),
				true
			);

			return;
		}

		if ('POST' === ($_SERVER['REQUEST_METHOD'] ?? '')) {
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
		$nonce = self::post_text('_wpnonce');

		if (!wp_verify_nonce($nonce, 'jmfa_step_' . (int) $pending->id)) {
			self::render_stage($pending, $user, __('เซสชันไม่ถูกต้อง กรุณาลองใหม่', 'jplugin-mfa'));

			return;
		}

		$action = sanitize_key(self::post_text('jmfa_action'));
		if ('codes' === $pending->stage) {
			if ('finish' === $action) {
				self::complete_login($pending, $user, 'login_ok');
			}
			self::render_stage($pending, $user);
			return;
		}

		if ('code' !== $action && !('verify' === $pending->stage && 'recovery' === $action)) {
			self::render_stage($pending, $user, __('ขั้นตอนไม่ถูกต้อง', 'jplugin-mfa'));
			return;
		}

		$limit = max(3, (int) JMFA_Policy::get('max_attempts', 5));
		if (!JMFA_Store::reserve_attempt($pending, $limit)) {
			self::render_locked();
			return;
		}

		if ('recovery' === $action) {
			$code = self::post_text('jmfa_recovery');

			if (JMFA_Store::consume_recovery_code($user->ID, $code, $pending->generation)) {
				JMFA_Audit::log('recovery_used', $user->ID);
				self::complete_login($pending, $user, 'login_ok_recovery');

				return;
			}

			self::register_failure($pending, $user, __('รหัสสำรองไม่ถูกต้องหรือถูกใช้ไปแล้ว', 'jplugin-mfa'));

			return;
		}

		$code = self::post_text('jmfa_code');

		if ('enroll' === $pending->stage) {
			$secret = JMFA_Crypto::decrypt($pending->setup_secret);
			$result = JMFA_Enroll::confirm($user->ID, $code, $pending->generation, $secret, $pending);

			if (is_wp_error($result)) {
				self::register_failure($pending, $user, $result->get_error_message());

				return;
			}

			self::set_cookie(self::current_token());
			self::render_codes($pending, $result);
			exit;
		}

		if (!JMFA_Store::consume_totp($user->ID, $code, $pending->generation)) {
			self::register_failure($pending, $user, __('รหัสไม่ถูกต้อง หรือเวลาในอุปกรณ์ไม่ตรงกับเซิร์ฟเวอร์', 'jplugin-mfa'));

			return;
		}

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
		$fresh    = JMFA_Store::get_pending_by_id((int) $pending->id);
		if (!$fresh || $fresh->stage !== $pending->stage) {
			self::expire_pending();
		}

		$attempts = (int) $fresh->attempts;
		$max      = max(3, (int) JMFA_Policy::get('max_attempts', 5));

		JMFA_Audit::log('verify_fail', $user->ID, array('attempts' => $attempts));

		if ($attempts >= $max) {
			JMFA_Audit::log('locked', $user->ID);
			self::render_locked();

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
		if (!JMFA_Store::claim_pending($pending)) {
			self::expire_pending();
		}

		self::clear_cookie();

		$context = $pending->context;
		wp_set_auth_cookie((int) $user->ID, (bool) $pending->remember, !empty($context['secure']));

		/** This action is documented in wp_signon(). */
		do_action('wp_login', $user->user_login, $user);

		JMFA_Audit::log($event, $user->ID);

		$redirect = apply_filters('login_redirect', $pending->redirect_to, $context['requested'], $user);
		if (!empty($context['interim'])) {
			self::render_interim_success(!empty($context['customizer']));
		}

		if (empty($redirect) || 'wp-admin/' === $redirect || admin_url() === $redirect) {
			if (is_multisite() && !get_active_blog_for_user($user->ID) && !is_super_admin($user->ID)) {
				$redirect = user_admin_url();
			} elseif (is_multisite() && !$user->has_cap('read')) {
				$redirect = get_dashboard_url($user->ID);
			} elseif (!$user->has_cap('edit_posts')) {
				$redirect = $user->has_cap('read') ? admin_url('profile.php') : home_url();
			}
		}

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
				self::render_codes($pending);
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
		$secret = JMFA_Crypto::decrypt($pending->setup_secret);

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
	 * @param array  $codes   Plain codes shown only on the successful setup response.
	 */
	private static function render_codes($pending, array $codes = array()) {
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

	private static function render_interim_success($customizer) {
		$GLOBALS['interim_login'] = 'success';
		if ($customizer) {
			add_action('login_enqueue_scripts', static function () {
				wp_enqueue_script('customize-base');
				wp_add_inline_script(
					'customize-base',
					'new wp.customize.Messenger({url: ' . wp_json_encode(wp_customize_url(), JSON_HEX_TAG) . ', channel: "login"}).send("login");'
				);
			});
		}

		login_header('', '<p class="message">' . esc_html__('You have logged in successfully.') . '</p>');
		self::close_page();
		exit;
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
		return JMFA_Store::get_pending(self::current_token());
	}

	private static function current_token() {
		$token = $_COOKIE[self::COOKIE] ?? '';

		return is_string($token) ? wp_unslash($token) : '';
	}

	private static function post_text($key) {
		$value = $_POST[$key] ?? '';

		return is_string($value) ? sanitize_text_field(wp_unslash($value)) : '';
	}

	private static function password_stamp($user) {
		return JMFA_Crypto::hmac('pending-password|' . $user->user_pass);
	}

	/**
	 * @param object $pending Pending row.
	 */
	private static function discard_pending($pending) {
		JMFA_Store::delete_pending((int) $pending->id);
		self::clear_cookie();
	}

	private static function expire_pending($pending = null) {
		if ($pending) {
			self::discard_pending($pending);
		}

		self::render_message(
			__('เซสชันหมดอายุ', 'jplugin-mfa'),
			__('การยืนยันตัวตนหมดอายุหรือถูกยกเลิก กรุณาเข้าสู่ระบบใหม่', 'jplugin-mfa')
		);
	}

	private static function render_locked() {
		self::render_message(
			__('พยายามมากเกินไป', 'jplugin-mfa'),
			__('กรอกรหัสผิดหลายครั้งเกินไป กรุณาเข้าสู่ระบบใหม่ตั้งแต่ต้น', 'jplugin-mfa')
		);
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
	 * @return bool
	 */
	private static function set_cookie($token) {
		if ('' === $token || headers_sent()) {
			return false;
		}

		$sent = setcookie(
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

		if ($sent) {
			$_COOKIE[ self::COOKIE ] = $token;
		}

		return $sent;
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
	private static function cancel_pending_from_cookie() {
		$token = self::current_token();
		if ('' !== $token) {
			JMFA_Store::delete_pending_by_token($token);
			self::clear_cookie();
		}
	}

	public static function on_logout_form() {
		self::cancel_pending_from_cookie();
		add_action('wp_logout', array(__CLASS__, 'on_logout'));
	}

	/**
	 * @param int $user_id User ID.
	 */
	public static function on_logout($user_id = 0) {
		if ($user_id && JMFA_Policy::get('mode') !== JMFA_Policy::MODE_OFF && !JMFA_Policy::is_disabled()) {
			JMFA_Audit::log('logout', (int) $user_id);
		}
	}

	/**
	 * Styles and scripts for the second step only.
	 */
	public static function enqueue() {
		$action = $_REQUEST['action'] ?? '';

		if ('jmfa' !== $action) {
			return;
		}

		wp_enqueue_style('jmfa-login', JMFA_URL . 'assets/css/jmfa.css', array(), JMFA_VERSION);
		// wp-login.php prints enqueued scripts in the head, not in the footer.
		wp_enqueue_script('jmfa-qr', JMFA_URL . 'assets/js/qrcode.js', array(), '1.4.4', false);
		wp_enqueue_script('jmfa-login', JMFA_URL . 'assets/js/jmfa.js', array('jmfa-qr'), JMFA_VERSION, false);
	}
}
