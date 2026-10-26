<?php
/**
 * Inbound plugin ZIP installer, without any server-side network download.
 *
 * @package WordPress_Abilities_Bridge
 */

namespace WP_Ability;

defined( 'ABSPATH' ) || exit;

/**
 * Accept a bounded Base64 ZIP, verify it, then delegate deployment to Core.
 */
final class Plugin_Upload_Installer {

	/**
	 * Maximum decoded ZIP size (12 MiB).
	 */
	const MAX_UPLOAD_BYTES = 12582912;

	/**
	 * Maximum cumulative uncompressed ZIP size (128 MiB).
	 */
	const MAX_UNPACKED_BYTES = 134217728;

	/**
	 * Maximum number of ZIP entries.
	 */
	const MAX_ZIP_ENTRIES = 10000;

	/**
	 * Optional upgrader factory (tests).
	 *
	 * @var callable|null
	 */
	private $upgrader_factory;

	/**
	 * Optional activation callback (tests).
	 *
	 * @var callable|null
	 */
	private $activator;

	/**
	 * Optional active-state callback (tests).
	 *
	 * @var callable|null
	 */
	private $active_checker;

	/**
	 * Create the installer.
	 *
	 * @param callable|null $upgrader_factory Optional upgrader factory.
	 * @param callable|null $activator        Optional activation callback.
	 * @param callable|null $active_checker   Optional active-state checker.
	 */
	public function __construct( $upgrader_factory = null, $activator = null, $active_checker = null ) {
		$this->upgrader_factory = $upgrader_factory;
		$this->activator        = $activator;
		$this->active_checker   = $active_checker;
	}

	/**
	 * Validate a Base64 ZIP package and deploy it with the WordPress upgrader.
	 *
	 * @param array $input Upload payload and options.
	 * @return array|\WP_Error
	 */
	public function install( array $input ) {
		$slug      = isset( $input['plugin_slug'] ) && is_string( $input['plugin_slug'] ) ? $input['plugin_slug'] : '';
		$checksum  = isset( $input['expected_sha256'] ) && is_string( $input['expected_sha256'] ) ? $input['expected_sha256'] : '';
		$payload   = isset( $input['zip_base64'] ) && is_string( $input['zip_base64'] ) ? $input['zip_base64'] : '';
		$overwrite = ! empty( $input['overwrite'] );
		$activate  = ! empty( $input['activate'] );

		// The API callback also checks permissions. Recheck here for direct callers.
		if ( ! current_user_can( 'install_plugins' ) ||
			( $overwrite && ! current_user_can( 'update_plugins' ) ) ||
			( $activate && ! current_user_can( 'activate_plugins' ) )
		) {
			return new \WP_Error( 'wp_ability_plugin_upload_forbidden', __( 'Insufficient permissions to upload this plugin.', 'wp-ability' ) );
		}

		if ( 1 !== preg_match( '/^[a-z0-9][a-z0-9_-]*$/D', $slug ) || 'wp-ability' === $slug ) {
			return new \WP_Error( 'wp_ability_plugin_upload_slug_invalid', __( 'A valid, non-self plugin slug is required.', 'wp-ability' ) );
		}

		if ( 1 !== preg_match( '/^[a-fA-F0-9]{64}$/D', $checksum ) ) {
			return new \WP_Error( 'wp_ability_invalid_package_checksum', __( 'Expected SHA-256 must be 64 hexadecimal characters.', 'wp-ability' ) );
		}

		// Reject excessively large or malformed input before allocating binary data.
		$encoded_max = (int) ceil( self::MAX_UPLOAD_BYTES / 3 ) * 4;
		$length      = strlen( $payload );

		if ( 0 === $length || $length > $encoded_max || 0 !== ( $length % 4 ) ||
			1 !== preg_match( '/\A[A-Za-z0-9+\/]+={0,2}\z/D', $payload )
		) {
			return new \WP_Error( 'wp_ability_plugin_upload_payload_invalid', __( 'Base64 ZIP payload is invalid or exceeds the maximum size.', 'wp-ability' ) );
		}

		$binary = base64_decode( $payload, true );
		unset( $payload );

		if ( false === $binary || strlen( $binary ) > self::MAX_UPLOAD_BYTES ) {
			return new \WP_Error( 'wp_ability_plugin_upload_payload_invalid', __( 'Base64 ZIP payload is invalid or too large.', 'wp-ability' ) );
		}

		if ( ! hash_equals( strtolower( $checksum ), hash( 'sha256', $binary ) ) ) {
			return new \WP_Error( 'wp_ability_package_checksum_mismatch', __( 'Uploaded ZIP SHA-256 does not match the expected digest.', 'wp-ability' ) );
		}

		if ( ! class_exists( '\ZipArchive' ) ) {
			return new \WP_Error( 'wp_ability_plugin_upload_zip_unavailable', __( 'PHP ZipArchive is required for safe upload validation.', 'wp-ability' ) );
		}

		require_once ABSPATH . 'wp-admin/includes/file.php';
		require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
		require_once ABSPATH . 'wp-admin/includes/plugin.php';

		$temp = wp_tempnam( $slug . '.zip' );
		if ( ! is_string( $temp ) || '' === $temp ) {
			return new \WP_Error( 'wp_ability_plugin_upload_temp_unavailable', __( 'Cannot create a temporary plugin ZIP.', 'wp-ability' ) );
		}

		try {
			if ( strlen( $binary ) !== file_put_contents( $temp, $binary, LOCK_EX ) ) {
				return new \WP_Error( 'wp_ability_plugin_upload_write_failed', __( 'Unable to write the temporary ZIP.', 'wp-ability' ) );
			}
			unset( $binary );

			$validation = $this->validate_archive( $temp, $slug );
			if ( is_wp_error( $validation ) ) {
				return $validation;
			}

			$upgrader = $this->create_upgrader();
			if ( is_wp_error( $upgrader ) ) {
				return $upgrader;
			}

			// The local file path bypasses Core's HTTP download operation.
			$result = $upgrader->install(
				$temp,
				array(
					'overwrite_package'  => $overwrite,
					'clear_update_cache' => true,
				)
			);

			if ( is_wp_error( $result ) ) {
				return $result;
			}
			if ( isset( $upgrader->skin->result ) && is_wp_error( $upgrader->skin->result ) ) {
				return $upgrader->skin->result;
			}
			if ( false === $result ) {
				return new \WP_Error( 'wp_ability_plugin_upload_install_failed', __( 'WordPress could not install the uploaded ZIP.', 'wp-ability' ) );
			}

			$plugin_file = $upgrader->plugin_info();
			if ( ! is_string( $plugin_file ) || '' === $plugin_file ||
				0 !== strpos( $plugin_file, $slug . '/' )
			) {
				return new \WP_Error( 'wp_ability_plugin_upload_target_mismatch', __( 'The resulting plugin does not match the requested slug.', 'wp-ability' ) );
			}

			wp_clean_plugins_cache( false );
			$activated = false;
			if ( $activate ) {
				$activation = is_callable( $this->activator )
					? call_user_func( $this->activator, $plugin_file )
					: activate_plugin( $plugin_file );
				if ( is_wp_error( $activation ) ) {
					return $activation;
				}
				$is_active = is_callable( $this->active_checker )
					? (bool) call_user_func( $this->active_checker, $plugin_file )
					: is_plugin_active( $plugin_file );
				if ( ! $is_active ) {
					return new \WP_Error( 'wp_ability_plugin_activation_unverified', __( 'Plugin activation could not be verified.', 'wp-ability' ) );
				}
				$activated = true;
			}

			$response = array(
				'plugin_file' => $plugin_file,
				'installed'   => true,
				'overwritten' => $overwrite,
				'activated'   => $activated,
			);
			$plugins = get_plugins();
			if ( isset( $plugins[ $plugin_file ]['Version'] ) ) {
				$response['version'] = $plugins[ $plugin_file ]['Version'];
			}

			return $response;
		} finally {
			// Never leave uploaded executable plugin packages on disk.
			if ( file_exists( $temp ) ) {
				wp_delete_file( $temp );
			}
		}
	}

	/**
	 * Validate structure, paths and archive expansion before the Core upgrader.
	 *
	 * @param string $path Temporary ZIP path.
	 * @param string $slug Expected package folder.
	 * @return true|\WP_Error
	 */
	private function validate_archive( $path, $slug ) {
		$zip = new \ZipArchive();
		if ( true !== $zip->open( $path, \ZipArchive::CHECKCONS ) ) {
			return new \WP_Error( 'wp_ability_plugin_upload_not_zip', __( 'Uploaded file is not a valid ZIP archive.', 'wp-ability' ) );
		}

		try {
			if ( 0 === $zip->numFiles || $zip->numFiles > self::MAX_ZIP_ENTRIES ) {
				return $this->unsafe_archive();
			}

			$total      = 0;
			$php_files  = 0;
			for ( $i = 0; $i < $zip->numFiles; ++$i ) {
				$stat = $zip->statIndex( $i );
				$name = is_array( $stat ) && isset( $stat['name'] ) ? $stat['name'] : '';

				if ( ! is_string( $name ) || '' === $name ||
					1 === preg_match( '/[\x00-\x1f\\\\]/', $name ) ||
					'/' === $name[0] || false !== strpos( $name, '//' )
				) {
					return $this->unsafe_archive();
				}

				$parts = explode( '/', rtrim( $name, '/' ) );
				if ( $slug !== $parts[0] ) {
					return new \WP_Error( 'wp_ability_plugin_upload_target_mismatch', __( 'ZIP root directory does not match plugin_slug.', 'wp-ability' ) );
				}
				foreach ( $parts as $part ) {
					if ( '' === $part || '.' === $part || '..' === $part ) {
						return $this->unsafe_archive();
					}
				}

				if ( count( $parts ) === 1 && '/' !== substr( $name, -1 ) ) {
					return $this->unsafe_archive();
				}

				$opsys = 0;
				$attrs = 0;
				if ( $zip->getExternalAttributesIndex( $i, $opsys, $attrs ) &&
					0120000 === ( ( $attrs >> 16 ) & 0170000 )
				) {
					return $this->unsafe_archive();
				}

				$total += (int) $stat['size'];
				if ( $total > self::MAX_UNPACKED_BYTES ) {
					return $this->unsafe_archive();
				}

				if ( count( $parts ) >= 2 && preg_match( '/\.php$/i', $name ) ) {
					++$php_files;
				}
			}
			if ( 0 === $php_files ) {
				return $this->unsafe_archive();
			}

			return true;
		} finally {
			$zip->close();
		}
	}

	/**
	 * Reject suspicious ZIP structure without exposing uploaded contents.
	 *
	 * @return \WP_Error
	 */
	private function unsafe_archive() {
		return new \WP_Error( 'wp_ability_plugin_upload_unsafe_zip', __( 'ZIP archive has an unsafe or unsupported structure.', 'wp-ability' ) );
	}

	/**
	 * Create the WordPress native upgrader.
	 *
	 * @return object|\WP_Error
	 */
	private function create_upgrader() {
		if ( is_callable( $this->upgrader_factory ) ) {
			return call_user_func( $this->upgrader_factory );
		}

		if ( ! class_exists( '\Automatic_Upgrader_Skin' ) || ! class_exists( '\Plugin_Upgrader' ) ) {
			return new \WP_Error( 'wp_ability_plugin_upgrader_unavailable', __( 'WordPress plugin upgrader is unavailable.', 'wp-ability' ) );
		}

		return new \Plugin_Upgrader( new \Automatic_Upgrader_Skin() );
	}
}
