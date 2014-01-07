<?php
/*
Plugin Name: HTAuth Sync
Plugin URI: http://wordpress.org/extend/plugins/htauth-sync
Description: Exports Wordpress credentials for use by Apache Digest Authentication
Author: John Luetke
Version: 1.1
Author URI: http://johnluetke.net
*/

//   Copyright 2013 John Luetke
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

if (!class_exists('HTAuthSync')) {

	if (!function_exists('debug')) {
		function debug($info, $function, $file, $line) {
			if (false) {
				//echo "<!--";
				echo "<pre>";
				echo "[" . basename($file) . ":" . $line . "]";
				print_r($info);
				echo "</pre>";
				//echo "-->";
			}
		}
	}

	define("HTDIGESTSYNC_OPTIONS", 'htauth-sync-options');
	define("HTDIGESTSYNC_DEFAULT_OPTIONS", serialize ( array (
			'htauth_file' => "",
			'htauth_realm' => "",
			'htauth_roles' => array()
	)));


	class HTAuthSync {
	
		private $options;
		
		public function __construct() {
			$this->refresh();
			debug($this, __FUNCTION__, __FILE__, __LINE__);
		}
	
		public static function activate() {
			update_option(HTDIGESTSYNC_OPTIONS, unserialize(HTDIGESTSYNC_DEFAULT_OPTIONS));
		}
	
		public static function deactivate() {
			delete_option(HTDIGESTSYNC_OPTIONS);
		}

		/**
		 */
		private function refresh() {
			$defaultOptions = unserialize(HTDIGESTSYNC_DEFAULT_OPTIONS);

			$this->options = array_merge($defaultOptions, get_option(HTDIGESTSYNC_OPTIONS));

			debug($this, __FUNCTION__, __FILE__, __LINE__);
		}

		/**
		 * Determines if a user exists in the htauth file
		 *
		 * @param string $username the user to look for
		 */
		private function userExists($username) {
		
			$users = $this->readFile();

			foreach ($users as $user) {
				$user_part = split(":", $user);
				if ($user_part[0] == $username)
					return true;
			}

			return false;
		}

		/**
		 * Adds new user to the file.
		 *
		 * @param string $username the user to add
		 * @param string $password user's password
		 */
		private function addUser($username, $password = "") {
			
			debug(func_get_args(), __FUNCTION__, __FILE__, __LINE__);

			$users = $this->readFile();

			$user = $this->getUserEntry($username, $password) . ((empty($password)) ? " # Not Synchronized" : "");
			$users[] = $user;

			debug($user, __FUNCTION__, __FILE__, __LINE__);

			$this->writeFile($users);
		}

		/**
		 * Removes a user from the htauth file. This is usually invoked when a user's
		 * role no longer is contained within those selected in the plugin's options. This
		 *
		 * @param string $username username to remove
		 */
		function removeUser($username) {
			
			$users = $this->readFile();

			debug($users, __FUNCTION__, __FILE__, __LINE__);

			for( $i = 0; $i < sizeof($users); $i++ ) {
				$user_part = split(":", $users[$i]);
				if (	($user_part[0] == $username) &&
					($user_part[1] == $this->options['htauth_realm'])) {
					unset($users[$i]);
				}
			}

			debug($users, __FUNCTION__, __FILE__, __LINE__);
		
			$this->writeFile($users);
		}
		
		/**
		 * Adds a new user to the htauth file or sets the password of a user in the htauth
		 * file. 
		 * 
		 * A new user is added when their role is contained wthin those set in the plugin's
		 * options. Thier password will not be hashed in the file until they login via Wordpress.
		 *
		 * A user is updated when thier hashed password in the file does not match the hashed
		 * password they used to log into Wordpress. The hashed password that they used to log in
		 * will be written to the file.
		 * 
		 * @param string $username username to remove
		 * @param string $password plain text password of the user
		 */
		function updateUser($username, $password) {
			
			$users = $this->readFile();
		
			debug($username, __FUNCTION__, __FILE__, __LINE__);
			debug($password, __FUNCTION__, __FILE__, __LINE__);

			$found = false;
			foreach( $users as &$user ) {
				$user_part = split(":", $user);
				if (	($user_part[0] == $username) &&
					($user_part[1] == $this->options['htauth_realm'])) {
					// If user_part[2] contains # and password is blank, do nothing, else, update the pw
					if (strpos($user_part[2], "#") >= 0 && empty($password)) {
						$found = true;
						continue;
					}
					else if ($user_part[2] != $this->getUserHash($username, $password)) {
						$found = true;
						$user = $this->getUserEntry($username, $password);
					}
				}
			}
		
			if (!$found)
				$users[] = $this->getUserEntry($username, "") . " # Not Synchronized";
		
			debug($users, __FUNCTION__, __FILE__, __LINE__);

			$this->writeFile($users);
		}
		
		/**
		 * Filter function that we use to hook into the Wordpress authentication process. Since
		 * this is technically a filter function, we need to return a WP_User object.
		 *
		 * When core WP trigger's this, the user has not yet authenticated. So we do that here
		 * to ensure that the password they typed in is indeed correct. 
		 *
		 * @param WP_User $user user that is trying to authenticate
		 * @param string $password plaintext password that the user entered into wp-login.php
		 *
		 * @return WP_User unaltered $user that was passed in
		 */
		function onUserAuthenticate($user, $password) {

			debug(func_get_args(), __FUNCTION__, __FILE__, __LINE__);

			if ( wp_check_password($password, $user->data->user_pass, $user->ID) ) {
				if (sizeof(array_intersect($user->roles, $this->options['htauth_roles'])) > 0) {
					if ($this->userExists($user->user_login)) {
						debug("Update", __FUNCTION__, __FILE__, __LINE__);
						$this->updateUser($user->user_login, $password);
					}
					else {
						debug("Add", __FUNCTION__, __FILE__, __LINE__);
						$this->addUser($user->user_login, $password);
					}
				}
			}
		
			return $user; 
		}
		
		/**
		 * Action hook for when a user's profile is updated. This function inspects $_POST data.
		 *
		 * If the user's password was changed, this will update it in the htauth file.
		 *
		 * If the user's role was changed, this will add them to the htauth file. They will
		 * need to log into Wordpress or reset their password via thier profile page.
		 *
		 * @param int $user_id ID of the user that was updated.
		 *
		 */
		public function onProfileUpdate ( $user_id ) {
			
			$user = get_userdata($user_id);
			
			debug($this, __FUNCTION__, __FILE__, __LINE__);
			debug($_POST, __FUNCTION__, __FILE__, __LINE__);
			debug($user, __FUNCTION__, __FILE__, __LINE__);
			
			// Is the role a syncable role?
			if (!in_array($_POST['role'], $this->options['htauth_roles'])) {
				debug("Remove user", __FUNCTION__, __FILE__, __LINE__);
				$this->removeUser($user->user_login);
			}
			else {
				$newPassword =  (!empty($_POST['pass1']) && !empty($_POST['pass2'])) &&
						($_POST['pass1'] == $_POST['pass2']);

				if (!$newPassword && $this->userExists($user->user_login)) {
					// nothing to do
					debug("Nothing to do :-)", __FUNCTION__, __FILE__, __LINE__);
				}
				else if ($newPassword && !$this->userExists($user->user_login)) {
					debug("Add User", __FUNCTION__, __FILE__, __LINE__);
					$this->addUser($user->user_login, $_POST['pass1']);
				}
				else if ($newPassword && $this->userExists($user->user_login)) {
					debug("Update User",  __FUNCTION__, __FILE__, __LINE__);
					$this->updateUser($user->user_login, $_POST['pass1']);
				}
				else if (!$this->userExists($user->user_login)) {
					debug("Add User", __FUNCTION__, __FILE__, __LINE__);
					$this->addUser($user->user_login);
				}
				else {
					// ignore 
				}
			}	
		}
		
		/**
		 * Reads the htauth file into an array. Each line of the file is an element.
		 *
		 * @param string $file the htauth file
		 *
		 * @return array entries from the htauth file.
		 */
		private function readFile( $removeComments = false ) {
			
			$users = file($this->options['htauth_file']);
		
			for( $i = 0; $i < sizeof($users); $i++) {

				//debug((strpos($users[$i], "#") !== false) . " --> " .$users[$i], __FUNCTION__, __FILE__, __LINE__);

				if (!strncmp($users[$i], "#", 1)) {
					array_splice($users, $i, 1);
					$i = 0;
				}
				else if ($removeComments && strpos($users[$i], "#") !== false) {
					$users[$i] = trim(substr($users[$i], "0", strpos($users[$i], "#")));
				}
				else
					$users[$i] = trim($users[$i]);
			}
		

			debug($users, __FUNCTION__, __FILE__, __LINE__);

			return array_values($users);
		}
		
		/**
		 * Writes an array to the htauth file
		 *
		 * @param string $file the htauth file
		 * @param array $users the lines to write to the file.
		 */
		private function writeFile($users) {
			
			sort($users);
		
			debug($users, __FUNCTION__, __FILE__, __LINE__);

			$hndl = fopen($this->options['htauth_file'], "w+");
			
			fwrite($hndl, "# Modified by HTAuthSync on " . date("M j Y H:i:s e") . "\n");

			foreach ( $users as $user )
				fwrite($hndl, trim($user) . "\n");
			
			fclose($hndl);
		}
		
		/**
		 * Calculates the hash to write to the file: $username:$realm:$password
		 *
		 * @param string $username username
		 * @param string $password plaintext password
		 *
		 * @return string hash to be written to the htauth file
		 */
		function getUserHash($username, $password) {
			return md5($username . ":" . $this->options['htauth_realm'] . ":" . $password);
		}
		
		/**
		 * Generates the line to write to the htauth file for a user: $username:$realm:$hash
		 *
		 * @param string $username username
		 * @param string $password plaintext password
		 *
		 * @return string user's entry in the file
		 */
		function getUserEntry($username, $password) {
			return $username . ":" . $this->options['htauth_realm'] . ":" . $this->getUserHash($username, $password);
		}
		
		/**
		 * Registers the options page fr the plugin
		 */
		public function registerOptionsPage() {
			add_options_page('HTAuth Sync', 'HTAuth Sync', 'manage_options', __FILE__, array($this, 'optionsPage'));
		}
		
		/**
		 * Generates the options page for the plugin
		 */
		public function optionsPage() {
		
			wp_enqueue_style( "htauthsync.css", plugins_url("htauthsync.css", __FILE__), array(), time() );

			if ($_POST) {
				$errors = array();;
				if (empty($_POST['htauth_file']))
					$errors[] = "Auth File location cannot be blank";
				if (empty($_POST['htauth_realm']))
					$errors[] = "Realm name cannot be blank";
				
				if (sizeof($errors) == 0) {
					update_option(HTDIGESTSYNC_OPTIONS, $_POST);
		?>
				<div class="updated"><p/>Options saved<p/></div>
		<?php
				}
				else {
		?>
				<div class="error"><p/><?php foreach ($errors as $error) { echo $error . "<p/>"; }?></div>
		<?php
				}

				$this->refresh();
			}
		
		?>
				<div class='wrap'>
				<div id="icon-options-general" class="icon32"></div>
				<h2>HTAuth Sync Settings</h2>
				<form method='post' action='<?php echo $_SERVER['PHP_SELF']; ?>?page=htauth-sync/htauthsync.php'>
				<table class="htauth-sync-options form-table">
					<tr>
						<th scope="row"><label for="htauth_file">Auth File location</label></th>
						<td>
							<input type="text" name="htauth_file" value="<?php echo $this->options['htauth_file'];?>" class="regular-text" />
							<p class="description">Absolute path to the file where your blog's users will be synced to. This value must also be entered as <a href="http://httpd.apache.org/docs/2.0/mod/mod_auth.html#authuserfile">AuthUserFile</a> in your Apache configuration. <strong>You should not put this file in a location where it can be accessed via a request to your webserver</strong>.</p>
							<div class="htauth-sync-warning"><strong>Warning!</strong> You should not change this value once the plugin has been active for some time. If you do, your users will need to re-login to Wordpress before their account will be synced.</div></td>
					</tr>
					<tr>
						<th scope="row"><label for="htauth_realm">Realm Name</label></th>
						<td>
							<input type="text" name="htauth_realm" value="<?php echo $this->options['htauth_realm'];?>" class="regular-text" />
							<p class="description">The "realm" that users will authenticate into. This value must also be entered as <a href="http://httpd.apache.org/docs/2.0/mod/core.html#authname">AuthName</a> in your Apache configuration.</p>
						</td>
					</tr>
					<tr>
		<?php
						$roles = get_editable_roles();
						//sort($roles);
		?>
						<th scope="row"><label for="htauth_roles[]">Roles to Sync</label></th>
						<td>
		<?php
							foreach ($roles as $role => $attrib) {
		?>
								<label>
									<input type="checkbox" name="htauth_roles[]" value="<?php echo $role;?>"<?php echo (in_array($role, $this->options['htauth_roles']) ? " checked=\"true\"" : "");?>/>
									<?php echo $attrib['name'];?>
								</label>
		<?php
							}
		?>
						</td>
					</tr>
					<tr>
						<td/>
						<td><input type="submit" class="button" value="Save Options" /></td>
				</table>
				</form>
				</div>
		<?php
		}
	}

	register_activation_hook( __FILE__, array('HTAuthSync', 'activate') );
	register_deactivation_hook(__FILE__, array('HTAuthSync', 'deactivate') );

	$HTAuthSync = new HTAuthSync();

	add_action( 'edit_user_profile_update', array($HTAuthSync, 'onProfileUpdate') );
	add_action( 'personal_options_update', array($HTAuthSync, 'onProfileUpdate') );
	add_filter( 'wp_authenticate_user', array($HTAuthSync, 'onUserAuthenticate'), 1, 3);

	add_action( 'admin_menu', array($HTAuthSync, 'registerOptionsPage'));
}
