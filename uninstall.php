<?php

/**
 * Removes credentials and short-lived authentication state on uninstall.
 *
 * @package WordPress\OpenAiAiProvider
 */

declare(strict_types=1);

use WordPress\OpenAiAiProvider\Authentication\AuthenticationMode;
use WordPress\OpenAiAiProvider\Authentication\EncryptedTokenStore;

if (!defined('WP_UNINSTALL_PLUGIN')) {
    return;
}

require_once __DIR__ . '/src/autoload.php';

/**
 * Removes OpenAI authentication data from the current site.
 *
 * @return void
 */
function ai_provider_for_openai_delete_authentication_data(): void
{
    delete_option(EncryptedTokenStore::OPTION_NAME);
    delete_option(AuthenticationMode::OPTION_NAME);
    delete_option(AuthenticationMode::API_KEY_OPTION_NAME);
    delete_option('_ai_provider_for_openai_oauth_refresh_lock');

    global $wpdb;
    if (!isset($wpdb) || !is_object($wpdb) || !isset($wpdb->options)) {
        return;
    }

    $prefixes = [
        '_ai_openai_oauth_poll_lock_',
        '_transient__ai_openai_oauth_session_',
        '_transient_timeout__ai_openai_oauth_session_',
    ];
    foreach ($prefixes as $prefix) {
        $like = $wpdb->esc_like($prefix) . '%';
        $query = $wpdb->prepare(
            "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s",
            $like
        );
        if (is_string($query)) {
            $wpdb->query($query);
        }
    }
}

if (is_multisite() && function_exists('get_sites')) {
    $siteIds = get_sites(['fields' => 'ids', 'number' => 0]);
    foreach ($siteIds as $siteId) {
        switch_to_blog((int) $siteId);
        ai_provider_for_openai_delete_authentication_data();
        restore_current_blog();
    }
} else {
    ai_provider_for_openai_delete_authentication_data();
}
