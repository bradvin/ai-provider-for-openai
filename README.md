# AI Provider for OpenAI

An AI Provider for OpenAI for the [PHP AI Client](https://github.com/WordPress/php-ai-client) SDK. Works as both a Composer package and a WordPress plugin.

## Requirements

- PHP 7.4 or higher
- When using with WordPress, requires WordPress 7.0 or higher
    - If using an older WordPress release, the [wordpress/php-ai-client](https://github.com/WordPress/php-ai-client) package must be installed

## Installation

### As a Composer Package

```bash
composer require wordpress/ai-provider-for-openai
```

### As a WordPress Plugin

1. Download the plugin files
2. Upload to `/wp-content/plugins/ai-provider-for-openai/`
3. Ensure the PHP AI Client plugin is installed and activated
4. Activate the plugin through the WordPress admin

## Usage

### With WordPress

The provider automatically registers itself with the PHP AI Client on the `init` hook. Simply ensure both plugins are active and configure your API key:

```php
// Set your OpenAI API key (or use the OPENAI_API_KEY environment variable)
putenv('OPENAI_API_KEY=your-api-key');

// Use the provider
$result = AiClient::prompt('Hello, world!')
    ->usingProvider('openai')
    ->generateTextResult();
```

### As a Standalone Package

```php
use WordPress\AiClient\AiClient;
use WordPress\OpenAiAiProvider\Provider\OpenAiProvider;

// Register the provider
$registry = AiClient::defaultRegistry();
$registry->registerProvider(OpenAiProvider::class);

// Set your API key
putenv('OPENAI_API_KEY=your-api-key');

// Generate text
$result = AiClient::prompt('Explain quantum computing')
    ->usingProvider('openai')
    ->generateTextResult();

echo $result->toText();
```

## Supported Models

Available models are dynamically discovered from the OpenAI API. This includes GPT models for text generation, DALL-E and GPT Image models for image generation, and TTS models for text-to-speech. See the [OpenAI documentation](https://platform.openai.com/docs/models) for the full list of available models.

## Configuration

### API key

The provider supports an OpenAI Platform API key from the WordPress Connectors screen or the `OPENAI_API_KEY` environment variable. You can set the environment variable via PHP:

```php
putenv('OPENAI_API_KEY=your-api-key');
```

API-key authentication uses the public `api.openai.com` API and supports all of this provider's text and image capabilities.

### OpenAI account (experimental)

On WordPress 7.0 and later, open **Settings > Connectors > OpenAI**, choose **OpenAI account (experimental)**, and select **Connect with OpenAI**. The plugin opens OpenAI's device verification page in a new tab, shows the one-time code, and completes the connection after you approve it.

This is the device authorization flow used by Codex clients. It uses the separate ChatGPT Codex backend and is not a replacement for OpenAI Platform API access. Account mode currently supports text generation and image inputs, but not image generation. The upstream endpoints and behavior are experimental and may change without notice.

OAuth access and refresh tokens are encrypted before they are stored in the WordPress database. Disconnecting the account removes them.

## External services

This plugin connects to OpenAI services. API-key mode sends model requests and prompt content to `api.openai.com`. When an administrator starts OpenAI account authentication, the plugin sends a Codex client identifier to `auth.openai.com`, polls the device authorization status, exchanges the approved code for tokens, and later refreshes those tokens. Account-mode model requests and prompt content are sent to `chatgpt.com/backend-api/codex`.

Review OpenAI's [Terms of Use](https://openai.com/policies/terms-of-use/), [Services Agreement](https://openai.com/policies/services-agreement/), and [Privacy Policy](https://openai.com/policies/privacy-policy/) before connecting.

## Extending OpenAI API profiles

The provider supports alternate OpenAI API dialects without requiring a fork. A custom request authentication implementation can implement `OpenAiApiProfileAwareAuthenticationInterface` and return an `OpenAiApiProfileInterface` instance. The profile can adapt operation support, endpoint URLs, requests, responses, model metadata, and model-cache isolation while the authentication object remains responsible for credentials.

The PHP AI Client currently validates replacement OpenAI authentication against its API-key DTO. Pass profile-aware authentication through `OpenAiApiProfileRequestAuthenticationAdapter` before registering it with `setProviderRequestAuthentication()`. The adapter only satisfies that registry compatibility check; request authentication and profile selection are delegated to the wrapped implementation.

WordPress integrations may also supply or replace a profile with the `ai_provider_for_openai_api_profile` filter. Profile request changes are applied before authentication, and response normalization is applied only after a successful HTTP response. Because a profile can change where authenticated requests are sent, only trusted code should provide one.

API-key authentication does not use a profile, so its existing request and cache behavior remains unchanged.

## License

GPL-2.0-or-later
