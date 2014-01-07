=== HTAuth Sync ===
Contributors: johnl1479
Donate link: http://johnluetke.net/donate
Tags: apache, htaccess, htauth, htusers, htdigest, authentication
Requires at least: 3.5
Tested up to: 3.8
Stable tag: 1.0.0
License: Apache License 2.0
License URI: http://www.apache.org/licenses/LICENSE-2.0.html

Synchronize your Wordpress users with a htusers file for authentication outside of Wordpress

== Description ==

Allow your Wordpress users to log into other systems using their Wordpress credentials! 

This plugin will create a htusers file and create entries for the user roles that you specify. When a user logs into Wordpress or updates their profile, their password is hashed and written to the file. The plugin handles password changes and resets automatically, so you can just set this up and forget about it!

== Installation ==

1. Unzip `htauthsync.zip` to the `/wp-content/plugins/` directory
1. Activate the plugin through the 'Plugins' menu in WordPress
1. Click "HTAuth Sync" in the "Settings" menu
1. Specify the location that you'd like your htusers file written to
1. In your Apache configuration, be sure that you specify the **AuthName** and **AuthUserFile** to be consistent with what you entered in the settings screen.

== Frequently asked questions ==

= Do I need to do anything when new user's join my site? =

Nope! Just specify the user roles that you would like synced, and the plugin takes care of the rest.

== Screenshots ==

== Upgrade Notice ==

Hopefully, there will never be anything here :-)

== Changelog ==

= 1.1 =
* Wordpress 3.8 compatibility
* Language Fixes
* UX improvements

= 1.0 =
* Initial Version
* Only exports in "digest" format.
