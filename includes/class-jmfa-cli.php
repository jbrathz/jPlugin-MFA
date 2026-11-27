<?php
/**
 * WP-CLI commands: break-glass access when the web UI is not reachable.
 *
 * @package jPlugin-MFA
 */

if (!defined('ABSPATH')) {
	exit;
}

class JMFA_CLI {

	/**
	 * Show two-factor status for every user that has it enabled.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Output format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp jmfa status
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function status($args, $assoc_args) {
		$ids = JMFA_Store::enabled_user_ids();
		$users = $ids ? get_users(array(
			'include' => $ids,
			'fields'  => array('ID', 'user_login', 'user_email'),
		)) : array();

		$rows = array();

		foreach ($users as $user) {
			$rows[] = array(
				'ID'        => $user->ID,
				'user_login' => $user->user_login,
				'user_email' => $user->user_email,
				'recovery'  => JMFA_Store::recovery_remaining($user->ID),
			);
		}

		if (!$rows) {
			WP_CLI::log('No user has two-factor enabled.');
			WP_CLI::log('Policy mode: ' . JMFA_Policy::get('mode', 'off'));

			return;
		}

		\WP_CLI\Utils\format_items(isset($assoc_args['format']) ? $assoc_args['format'] : 'table', $rows, array('ID', 'user_login', 'user_email', 'recovery'));
	}

	/**
	 * Remove two-factor for a user. The user can enrol again on next login.
	 *
	 * ## OPTIONS
	 *
	 * <user>
	 * : User login, email or ID.
	 *
	 * ## EXAMPLES
	 *
	 *     wp jmfa reset admin
	 *
	 * @param array $args Positional arguments.
	 */
	public function reset($args) {
		$user = $this->find_user(isset($args[0]) ? $args[0] : '');

		if (!JMFA_Store::disable($user->ID)) {
			WP_CLI::error('Unable to reset two-factor data.');
		}

		JMFA_Audit::log('cli_reset', $user->ID);
		JMFA_Enroll::destroy_sessions($user->ID);

		WP_CLI::success(sprintf('Two-factor removed for %s.', $user->user_login));
	}

	/**
	 * Same as reset, kept as an explicit alias.
	 *
	 * ## OPTIONS
	 *
	 * <user>
	 * : User login, email or ID.
	 *
	 * @param array $args Positional arguments.
	 */
	public function disable($args) {
		$this->reset($args);
	}

	/**
	 * Clear pending logins that were left half finished.
	 *
	 * ## OPTIONS
	 *
	 * [<user>]
	 * : Optional user. Without it every pending login is removed.
	 *
	 * @param array $args Positional arguments.
	 */
	public function unlock($args) {
		if (!empty($args[0])) {
			$user = $this->find_user($args[0]);
			JMFA_Store::delete_pending_for_user($user->ID);
			WP_CLI::success(sprintf('Pending logins cleared for %s.', $user->user_login));

			return;
		}

		JMFA_Store::purge_pending();
		WP_CLI::success('All pending logins cleared.');
	}

	/**
	 * @param string $identifier Login, email or ID.
	 * @return WP_User
	 */
	private function find_user($identifier) {
		$user = false;

		if (is_numeric($identifier)) {
			$user = get_user_by('id', (int) $identifier);
		}

		if (!$user) {
			$user = get_user_by('login', (string) $identifier);
		}

		if (!$user) {
			$user = get_user_by('email', (string) $identifier);
		}

		if (!$user) {
			WP_CLI::error('User not found.');
		}

		return $user;
	}
}

WP_CLI::add_command('jmfa', 'JMFA_CLI');
