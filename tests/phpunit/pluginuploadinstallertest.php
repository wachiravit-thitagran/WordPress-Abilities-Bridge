<?php
/**
 * Inbound ZIP upload installation regression tests.
 *
 * @package WordPress_Abilities_Bridge
 */

use WP_Ability\Plugin_Upload_Installer;

require_once __DIR__ . '/class-wpabilityfakepluginupgrader.php';

/**
 * Verify Base64 upload validation and WordPress upgrader delegation.
 */
class PluginUploadInstallerTest extends WP_UnitTestCase {

	/**
	 * Expected ZIP plugin directory.
	 */
	const SLUG = 'wp-ability-upload-fixture';

	/**
	 * Set up a privileged WordPress caller.
	 *
	 * @return void
	 */
	public function setUp(): void {
		parent::setUp();
		if ( ! class_exists( 'ZipArchive' ) ) {
			$this->markTestSkipped( 'ZipArchive extension is unavailable.' );
		}
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );
	}

	/**
	 * Make a Base64 ZIP fixture entirely in the test runtime.
	 *
	 * @param array|null $entries Optional archive entries.
	 * @return array
	 */
	private function fixture( $entries = null ) {
		$entries = null === $entries
			? array( self::SLUG . '/plugin.php' => "<?php\n/*\nPlugin Name: Upload Fixture\nVersion: 1.0.0\n*/\n" )
			: $entries;

		$path = wp_tempnam( 'wp-ability-unit-fixture.zip' );
		$zip  = new ZipArchive();
		$this->assertTrue( $zip->open( $path, ZipArchive::CREATE | ZipArchive::OVERWRITE ) );
		foreach ( $entries as $name => $content ) {
			$zip->addFromString( $name, $content );
		}
		$this->assertTrue( $zip->close() );
		$bytes = file_get_contents( $path );
		wp_delete_file( $path );
		$this->assertIsString( $bytes );

		return array(
			'plugin_slug'     => self::SLUG,
			'zip_base64'      => base64_encode( $bytes ),
			'expected_sha256' => hash( 'sha256', $bytes ),
			'overwrite'       => false,
			'activate'        => false,
		);
	}

	/**
	 * Make a fake Core upgrader for the fixture.
	 *
	 * @return WPAbilityFakePluginUpgrader
	 */
	private function upgrader() {
		$upgrader              = new WPAbilityFakePluginUpgrader();
		$upgrader->plugin_file = self::SLUG . '/plugin.php';
		return $upgrader;
	}

	/**
	 * Uploads call Core's native installer with a local temp path only.
	 *
	 * @return void
	 */
	public function test_verified_zip_uses_local_file_and_cleans_up(): void {
		$fake      = $this->upgrader();
		$installer = new Plugin_Upload_Installer(
			static function () use ( $fake ) {
				return $fake;
			}
		);
		$result = $installer->install( $this->fixture() );

		$this->assertIsArray( $result );
		$this->assertSame( self::SLUG . '/plugin.php', $result['plugin_file'] );
		$this->assertTrue( $result['installed'] );
		$this->assertFalse( $result['overwritten'] );
		$this->assertFalse( $result['activated'] );
		$this->assertIsString( $fake->package );
		$this->assertFalse( filter_var( $fake->package, FILTER_VALIDATE_URL ) );
		$this->assertFalse( file_exists( $fake->package ), 'Temporary ZIP must always be removed.' );
		$this->assertFalse( $fake->args['overwrite_package'] );
		$this->assertTrue( $fake->args['clear_update_cache'] );
	}

	/**
	 * Overwrites and activation use the expected WordPress API options.
	 *
	 * @return void
	 */
	public function test_overwrite_and_activation(): void {
		$fake      = $this->upgrader();
		$installer = new Plugin_Upload_Installer(
			static function () use ( $fake ) {
				return $fake;
			},
			static function () {
				return null;
			},
			static function () {
				return true;
			}
		);
		$input              = $this->fixture();
		$input['overwrite'] = true;
		$input['activate']  = true;
		$result             = $installer->install( $input );

		$this->assertIsArray( $result );
		$this->assertTrue( $fake->args['overwrite_package'] );
		$this->assertTrue( $result['overwritten'] );
		$this->assertTrue( $result['activated'] );
	}

	/**
	 * A checksum mismatch prevents executing any WordPress upgrader.
	 *
	 * @return void
	 */
	public function test_rejects_checksum_mismatch(): void {
		$input                    = $this->fixture();
		$input['expected_sha256'] = str_repeat( '0', 64 );
		$result                   = ( new Plugin_Upload_Installer() )->install( $input );

		$this->assertWPError( $result );
		$this->assertSame( 'wp_ability_package_checksum_mismatch', $result->get_error_code() );
	}

	/**
	 * SHA-256 must be provided, never silently skipped.
	 *
	 * @return void
	 */
	public function test_rejects_missing_checksum(): void {
		$input = $this->fixture();
		unset( $input['expected_sha256'] );
		$result = ( new Plugin_Upload_Installer() )->install( $input );

		$this->assertWPError( $result );
		$this->assertSame( 'wp_ability_invalid_package_checksum', $result->get_error_code() );
	}

	/**
	 * Base64 payloads must be strictly encoded.
	 *
	 * @return void
	 */
	public function test_rejects_invalid_base64(): void {
		$input               = $this->fixture();
		$input['zip_base64']  = '!!!!';
		$result              = ( new Plugin_Upload_Installer() )->install( $input );

		$this->assertWPError( $result );
		$this->assertSame( 'wp_ability_plugin_upload_payload_invalid', $result->get_error_code() );
	}

	/**
	 * A valid digest for a non-ZIP must still be refused.
	 *
	 * @return void
	 */
	public function test_rejects_non_zip_bytes(): void {
		$input                    = $this->fixture();
		$input['zip_base64']       = base64_encode( 'not a zip' );
		$input['expected_sha256']  = hash( 'sha256', 'not a zip' );
		$result                   = ( new Plugin_Upload_Installer() )->install( $input );

		$this->assertWPError( $result );
		$this->assertSame( 'wp_ability_plugin_upload_not_zip', $result->get_error_code() );
	}

	/**
	 * A ZIP cannot overwrite any unrelated target plugin.
	 *
	 * @return void
	 */
	public function test_rejects_unexpected_root_folder(): void {
		$input = $this->fixture( array( 'different-plugin/main.php' => '<?php // unrelated' ) );
		$result = ( new Plugin_Upload_Installer() )->install( $input );

		$this->assertWPError( $result );
		$this->assertSame( 'wp_ability_plugin_upload_target_mismatch', $result->get_error_code() );
	}

	/**
	 * Reject ZIP traversal entries before calling the upgrader.
	 *
	 * @return void
	 */
	public function test_rejects_zip_traversal(): void {
		$input = $this->fixture(
			array(
				self::SLUG . '/plugin.php'     => '<?php // test',
				self::SLUG . '/../escape.php' => '<?php // forbidden',
			)
		);
		$result = ( new Plugin_Upload_Installer() )->install( $input );

		$this->assertWPError( $result );
		$this->assertSame( 'wp_ability_plugin_upload_unsafe_zip', $result->get_error_code() );
	}

	/**
	 * An unauthorised caller is rejected even when directly invoking the service.
	 *
	 * @return void
	 */
	public function test_direct_call_requires_install_privilege(): void {
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'subscriber' ) ) );
		$result = ( new Plugin_Upload_Installer() )->install( $this->fixture() );

		$this->assertWPError( $result );
		$this->assertSame( 'wp_ability_plugin_upload_forbidden', $result->get_error_code() );
	}

	/**
	 * Uploading the bridge itself through its own running ability is unsafe.
	 *
	 * @return void
	 */
	public function test_rejects_self_overwrite(): void {
		$input                = $this->fixture();
		$input['plugin_slug'] = 'wp-ability';
		$result = ( new Plugin_Upload_Installer() )->install( $input );

		$this->assertWPError( $result );
		$this->assertSame( 'wp_ability_plugin_upload_slug_invalid', $result->get_error_code() );
	}

	/**
	 * Verify error propagation and temporary file cleanup.
	 *
	 * @return void
	 */
	public function test_propagates_upgrader_error_and_cleans_up(): void {
		$fake                 = $this->upgrader();
		$fake->install_result = new WP_Error( 'disk_full', 'Mock disk is full.' );
		$installer = new Plugin_Upload_Installer(
			static function () use ( $fake ) {
				return $fake;
			}
		);
		$result = $installer->install( $this->fixture() );
		$this->assertWPError( $result );
		$this->assertSame( 'disk_full', $result->get_error_code() );
		$this->assertFalse( file_exists( $fake->package ) );
	}
}
