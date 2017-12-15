<?php

namespace dfwood\WordPress;

/**
 * Class MultipleRoles
 * @author David Wood <david@davidwood.ninja>
 * @link https://davidwood.ninja/
 * @license GPLv3
 * @package dfwood\WordPress
 */
class MultipleRoles {

	/**
	 * Add actions to initialize functionality.
	 */
	public static function initialize() {
		add_action( 'restrict_manage_users', [ __CLASS__, '_userManagementOptions' ] );
		add_action( 'load-users.php', [ __CLASS__, '_bulkUserRoleEdit' ], 99 );
	}

	/**
	 * Outputs user role add/remove dropdowns.
	 *
	 * @internal Typically only called via WP action hook.
	 */
	public static function _userManagementOptions() {
		static $isAdded;
		if ( null === $isAdded && current_user_can( 'promote_users' ) ) {
			$isAdded = true;
			wp_nonce_field(
				__FILE__ . get_current_user_id() . __CLASS__,
				stripslashes( __CLASS__ ) . '-nonce'
			);
			?>
            <select name="<?php echo esc_attr( stripslashes( __CLASS__ ) . '-add-role' ); ?>">
                <option value=""><?php esc_html_e( 'Add role to user…', 'dfwood-wp-multiple-roles' ); ?></option>
				<?php wp_dropdown_roles(); ?>
            </select>
            <select name="<?php echo esc_attr( stripslashes( __CLASS__ ) . '-remove-role' ); ?>">
                <option value=""><?php esc_html_e( 'Remove role from user…', 'dfwood-wp-multiple-roles' ); ?></option>
				<?php wp_dropdown_roles(); ?>
            </select>
			<?php
		}
	}

	/**
	 * Handles processing bulk user role addition/removal logic from users page.
	 *
	 * @internal Typically only called via WP action hook.
	 */
	public static function _bulkUserRoleEdit() {
		if ( ! empty( $_GET[ stripslashes( __CLASS__ ) . '-nonce' ] ) && wp_verify_nonce(
				filter_input( INPUT_GET, stripslashes( __CLASS__ ) . '-nonce', FILTER_SANITIZE_STRING ),
				__FILE__ . get_current_user_id() . __CLASS__
			)
		) {
			$addRole = filter_input( INPUT_GET, stripslashes( __CLASS__ ) . '-add-role', FILTER_SANITIZE_STRING );
			$removeRole = filter_input( INPUT_GET, stripslashes( __CLASS__ ) . '-remove-role', FILTER_SANITIZE_STRING );
			$userIds = array_map( 'absint', filter_input( INPUT_GET, 'users', FILTER_DEFAULT, FILTER_REQUIRE_ARRAY ) );

			if ( ! empty( $userIds ) && ( ! empty( $addRole ) || ! empty( $removeRole ) ) ) {
				// Loop through all selected users and verify current user can edit them.
				foreach ( $userIds as $userId ) {
					// Verify user has permission to promote the user
					if ( ! current_user_can( 'promote_user', $userId ) ) {
						wp_die( sprintf(
						/* Translator note: %d is the user ID that cannot be edited. */
							esc_html__( 'You can\'t edit user with ID %d', 'dfwood-wp-multiple-roles' ),
							$userId
						) );
					}

					// If the user doesn't already belong to the blog, bail.
					if ( is_multisite() && ! is_user_member_of_blog( $userId ) ) {
						wp_die(
							'<h1>' . esc_html__( 'Cheatin&#8217; uh?', 'dfwood-wp-multiple-roles' ) . '</h1>' .
							'<p>' . esc_html__( 'One of the selected users is not a member of this site.', 'dfwood-wp-multiple-roles' ) . '</p>',
							403
						);
					}

					// Verify the user isn't trying to promote themselves, prevents accidental loss of privileges.
					if ( get_current_user_id() === $userId ) {
						wp_die( esc_html__( 'You are not allowed to edit your own user role(s)!', 'dfwood-wp-multiple-roles' ) );
					}
				}

				// If we make it here, then there are no known issues adding/removing requested roles.
				// We are doing a second loop to avoid updating any users if we can't update all of them.
				foreach ( $userIds as $userId ) {
					$user = get_userdata( $userId );

					if ( ! empty( $addRole ) ) {
						$user->add_role( $addRole );
					}

					if ( ! empty( $removeRole ) ) {
						$user->remove_role( $removeRole );
					}
				}

				// Go back to the users page, ensure our GET args are cleared out and show confirmation message.
				wp_safe_redirect( add_query_arg( 'update', 'promote', admin_url( 'users.php' ) ) );
				exit();
			}
		}
	}

}
