<?php

/**
 * Plugin Name: AI Provider for OpenAI
 * Plugin URI: https://github.com/WordPress/ai-provider-for-openai
 * Description: AI Provider for OpenAI for the WordPress AI Client.
 * Requires at least: 6.9
 * Requires PHP: 7.4
 * Version: 1.1.0
 * Author: WordPress AI Team
 * Author URI: https://make.wordpress.org/ai/
 * License: GPL-2.0-or-later
 * License URI: https://spdx.org/licenses/GPL-2.0-or-later.html
 * Text Domain: ai-provider-for-openai
 *
 * @package WordPress\OpenAiAiProvider
 */

declare(strict_types=1);

namespace WordPress\OpenAiAiProvider;

use Throwable;
use WordPress\AiClient\AiClient;
use WordPress\AiClient\Common\Contracts\CachesDataInterface;
use WordPress\OpenAiAiProvider\Admin\OAuthRestController;
use WordPress\OpenAiAiProvider\Authentication\AuthenticationMode;
use WordPress\OpenAiAiProvider\Authentication\OAuthTokenManager;
use WordPress\OpenAiAiProvider\Authentication\OpenAiApiProfileRequestAuthenticationAdapter;
use WordPress\OpenAiAiProvider\Authentication\OpenAiOAuthRequestAuthentication;
use WordPress\OpenAiAiProvider\Provider\OpenAiProvider;

if (!defined('ABSPATH')) {
    return;
}

require_once __DIR__ . '/src/autoload.php';

/**
 * Registers the AI Provider for OpenAI with the AI Client.
 *
 * @since 1.0.0
 *
 * @return void
 */
function register_provider(): void
{
    if (!class_exists(AiClient::class)) {
        return;
    }

    $registry = AiClient::defaultRegistry();

    if ($registry->hasProvider(OpenAiProvider::class)) {
        return;
    }

    $registry->registerProvider(OpenAiProvider::class);
}

/**
 * Gets the site-wide OAuth token manager used for provider requests.
 *
 * @since 1.1.0
 *
 * @return OAuthTokenManager The shared token manager.
 */
function oauth_token_manager(): OAuthTokenManager
{
    static $tokenManager = null;

    if (!$tokenManager instanceof OAuthTokenManager) {
        $tokenManager = new OAuthTokenManager();
    }

    return $tokenManager;
}

/**
 * Replaces API-key authentication when OpenAI account mode is selected.
 *
 * The account authentication is installed even if stored token data has
 * become unreadable. That makes the selected mode fail closed instead of
 * silently falling back to a configured API key.
 *
 * @since 1.1.0
 *
 * @return void
 */
function configure_oauth_authentication(): void
{
    if (!class_exists(AiClient::class)) {
        return;
    }

    $mode = new AuthenticationMode();
    if ($mode->get() !== AuthenticationMode::MODE_OAUTH) {
        return;
    }

    try {
        $registry = AiClient::defaultRegistry();
        if (!$registry->hasProvider(OpenAiProvider::class)) {
            return;
        }

        $registry->setProviderRequestAuthentication(
            OpenAiProvider::class,
            new OpenAiApiProfileRequestAuthenticationAdapter(
                new OpenAiOAuthRequestAuthentication(oauth_token_manager())
            )
        );
    } catch (Throwable $throwable) {
        if (function_exists('wp_trigger_error')) {
            wp_trigger_error(__FUNCTION__, $throwable->getMessage());
        }
    }
}

/**
 * Declares connected account credentials to WordPress AI integrations.
 *
 * Core connector metadata currently describes the OpenAI connector's API-key
 * setting. Consumers use this filter to recognize credential types that are
 * managed separately, such as this plugin's encrypted OAuth token pair.
 *
 * @since 1.1.0
 */
function include_oauth_credentials(bool $hasCredentials): bool
{
    if ($hasCredentials) {
        return true;
    }

    if ((new AuthenticationMode())->get() !== AuthenticationMode::MODE_OAUTH) {
        return false;
    }

    try {
        return is_array(oauth_token_manager()->getStoredTokenSet());
    } catch (Throwable $throwable) {
        return false;
    }
}

/**
 * Registers the OAuth administration REST routes.
 *
 * @since 1.1.0
 *
 * @return void
 */
function register_oauth_rest_routes(): void
{
    $controller = new OAuthRestController();
    $controller->registerRoutes();
}

/**
 * Clears model metadata after an authentication or token change.
 *
 * @since 1.1.0
 *
 * @return void
 */
function invalidate_model_metadata_cache(): void
{
    if (!class_exists(AiClient::class)) {
        return;
    }

    $directory = OpenAiProvider::modelMetadataDirectory();
    if (!$directory instanceof CachesDataInterface) {
        return;
    }

    try {
        $directory->invalidateCaches();
    } catch (Throwable $throwable) {
        /*
         * Cache invalidation is best effort. In particular, disconnecting an
         * account deletes its cache identity before the final auth-changed
         * notification. Profile-specific cache namespaces prevent that stale
         * entry from being reused by another authentication context.
         */
        unset($throwable);
    }
}

/**
 * Loads the custom OpenAI connector settings on the Connectors screen.
 *
 * @since 1.1.0
 *
 * @param string $hookSuffix The current admin page hook suffix.
 * @return void
 */
function enqueue_oauth_connector_assets(string $hookSuffix): void
{
    unset($hookSuffix);

    $screen = function_exists('get_current_screen') ? get_current_screen() : null;
    $screenId = is_object($screen) && isset($screen->id) && is_string($screen->id)
        ? $screen->id
        : '';
    $page = '';
    if (isset($_GET['page']) && is_string($_GET['page'])) {
        $page = function_exists('sanitize_key') && function_exists('wp_unslash')
            ? sanitize_key(wp_unslash($_GET['page']))
            : preg_replace('/[^a-z0-9_-]/', '', strtolower($_GET['page']));
    }

    if (
        $screenId !== 'options-connectors'
        && !in_array($page, ['options-connectors', 'options-connectors-wp-admin'], true)
    ) {
        return;
    }

    if (
        !function_exists('wp_register_script_module')
        || !function_exists('wp_enqueue_script_module')
    ) {
        return;
    }

    $scriptPath = __DIR__ . '/assets/js/openai-oauth-connector.js';
    $stylePath = __DIR__ . '/assets/css/openai-oauth-connector.css';
    $scriptVersion = file_exists($scriptPath) ? (string) filemtime($scriptPath) : '1.1.0';
    $styleVersion = file_exists($stylePath) ? (string) filemtime($stylePath) : '1.1.0';

    wp_register_script_module(
        'ai-provider-for-openai-oauth-connector',
        plugins_url('assets/js/openai-oauth-connector.js', __FILE__),
        [
            ['id' => '@wordpress/connectors', 'import' => 'static'],
        ],
        $scriptVersion
    );

    if (function_exists('wp_enqueue_script')) {
        wp_enqueue_script('wp-api-fetch');
        wp_enqueue_script('wp-components');
        wp_enqueue_script('wp-element');
        wp_enqueue_script('wp-i18n');
    }
    wp_enqueue_script_module('ai-provider-for-openai-oauth-connector');

    if (function_exists('wp_enqueue_style')) {
        wp_enqueue_style(
            'ai-provider-for-openai-oauth-connector',
            plugins_url('assets/css/openai-oauth-connector.css', __FILE__),
            [],
            $styleVersion
        );
    }
}

add_action('init', __NAMESPACE__ . '\\register_provider', 5);
add_action('init', __NAMESPACE__ . '\\configure_oauth_authentication', 25);
add_action('rest_api_init', __NAMESPACE__ . '\\register_oauth_rest_routes');
add_filter('wpai_has_ai_credentials', __NAMESPACE__ . '\\include_oauth_credentials');
add_action(
    'ai_provider_for_openai_auth_changed',
    __NAMESPACE__ . '\\invalidate_model_metadata_cache'
);
add_action(
    'admin_enqueue_scripts',
    __NAMESPACE__ . '\\enqueue_oauth_connector_assets',
    5
);
