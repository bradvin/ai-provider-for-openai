<?php

declare(strict_types=1);

use WordPress\AiClient\Messages\DTO\Message;
use WordPress\AiClient\Messages\DTO\MessagePart;
use WordPress\AiClient\Messages\Enums\MessageRoleEnum;
use WordPress\AiClient\Providers\DTO\ProviderMetadata;
use WordPress\AiClient\Providers\Enums\ProviderTypeEnum;
use WordPress\AiClient\Providers\Http\Contracts\HttpTransporterInterface;
use WordPress\AiClient\Providers\Http\DTO\Request;
use WordPress\AiClient\Providers\Http\DTO\RequestOptions;
use WordPress\AiClient\Providers\Http\DTO\Response;
use WordPress\AiClient\Providers\Models\DTO\ModelMetadata;
use WordPress\AiClient\Providers\Models\Enums\CapabilityEnum;
use WordPress\OpenAiAiProvider\Admin\OAuthRestController;
use WordPress\OpenAiAiProvider\Authentication\AuthenticationMode;
use WordPress\OpenAiAiProvider\Authentication\EncryptedTokenStore;
use WordPress\OpenAiAiProvider\Authentication\OAuthClient;
use WordPress\OpenAiAiProvider\Authentication\OAuthError;
use WordPress\OpenAiAiProvider\Authentication\OAuthFlow;
use WordPress\OpenAiAiProvider\Authentication\OAuthSessionStore;
use WordPress\OpenAiAiProvider\Authentication\OAuthTokenManager;
use WordPress\OpenAiAiProvider\Authentication\OpenAiOAuthRequestAuthentication;
use WordPress\OpenAiAiProvider\Metadata\OpenAiModelMetadataDirectory;
use WordPress\OpenAiAiProvider\Models\OpenAiCodexStreamResponseParser;
use WordPress\OpenAiAiProvider\Models\OpenAiCodexToolSchemaSanitizer;
use WordPress\OpenAiAiProvider\Models\OpenAiTextGenerationModel;

final class WP_Error
{
    /** @var string */
    private $code;

    /** @var string */
    private $message;

    /** @var mixed */
    private $data;

    /** @param mixed $data */
    public function __construct(string $code = '', string $message = '', $data = null)
    {
        $this->code = $code;
        $this->message = $message;
        $this->data = $data;
    }

    public function get_error_code(): string
    {
        return $this->code;
    }

    public function get_error_message(): string
    {
        return $this->message;
    }

    /** @return mixed */
    public function get_error_data()
    {
        return $this->data;
    }
}

/** @var array<string, mixed> */
$GLOBALS['oauth_test_options'] = [];
/** @var array<string, mixed> */
$GLOBALS['oauth_test_transients'] = [];
/** @var list<mixed> */
$GLOBALS['oauth_test_http_queue'] = [];
/** @var array<string, array<string, mixed>> */
$GLOBALS['oauth_test_routes'] = [];
/** @var string|null */
$GLOBALS['oauth_test_delete_failure'] = null;
/** @var array<string, list<callable|string>> */
$GLOBALS['oauth_test_filters'] = [];

/** @param mixed $value */
function is_wp_error($value): bool
{
    return $value instanceof WP_Error;
}

/** @param mixed $default @return mixed */
function get_option(string $name, $default = false)
{
    return array_key_exists($name, $GLOBALS['oauth_test_options'])
        ? $GLOBALS['oauth_test_options'][$name]
        : $default;
}

/** @param mixed $value @param mixed $deprecated @param mixed $autoload */
function add_option(string $name, $value, $deprecated = '', $autoload = 'yes'): bool
{
    unset($deprecated, $autoload);
    if (array_key_exists($name, $GLOBALS['oauth_test_options'])) {
        return false;
    }
    $GLOBALS['oauth_test_options'][$name] = $value;
    return true;
}

/** @param mixed $value @param mixed $autoload */
function update_option(string $name, $value, $autoload = null): bool
{
    unset($autoload);
    $GLOBALS['oauth_test_options'][$name] = $value;
    return true;
}

function delete_option(string $name): bool
{
    if ($GLOBALS['oauth_test_delete_failure'] === $name) {
        return false;
    }
    $existed = array_key_exists($name, $GLOBALS['oauth_test_options']);
    unset($GLOBALS['oauth_test_options'][$name]);
    return $existed;
}

function wp_salt(string $scheme = 'auth'): string
{
    return 'test-salt-' . $scheme . '-with-sufficient-entropy';
}

/** @param mixed ...$args */
function do_action(string $name, ...$args): void
{
    unset($name, $args);
}

/** @param callable|string $callback */
function add_action(string $name, $callback, int $priority = 10, int $acceptedArgs = 1): bool
{
    unset($name, $callback, $priority, $acceptedArgs);
    return true;
}

/** @param callable|string $callback */
function add_filter(string $name, $callback, int $priority = 10, int $acceptedArgs = 1): bool
{
    unset($priority, $acceptedArgs);
    $GLOBALS['oauth_test_filters'][$name][] = $callback;
    return true;
}

/** @return mixed */
function get_transient(string $name)
{
    return array_key_exists($name, $GLOBALS['oauth_test_transients'])
        ? $GLOBALS['oauth_test_transients'][$name]
        : false;
}

/** @param mixed $value */
function set_transient(string $name, $value, int $expiration = 0): bool
{
    unset($expiration);
    $GLOBALS['oauth_test_transients'][$name] = $value;
    return true;
}

function delete_transient(string $name): bool
{
    $existed = array_key_exists($name, $GLOBALS['oauth_test_transients']);
    unset($GLOBALS['oauth_test_transients'][$name]);
    return $existed;
}

/** @param array<string, mixed> $args @return mixed */
function wp_safe_remote_post(string $url, array $args = [])
{
    unset($url, $args);
    if (!$GLOBALS['oauth_test_http_queue']) {
        return new WP_Error('unexpected_http_request', 'No fake HTTP response was queued.');
    }
    return array_shift($GLOBALS['oauth_test_http_queue']);
}

/** @param mixed $response */
function wp_remote_retrieve_response_code($response): int
{
    return is_array($response) && isset($response['response']['code'])
        ? (int) $response['response']['code']
        : 0;
}

/** @param mixed $response */
function wp_remote_retrieve_body($response): string
{
    return is_array($response) && isset($response['body']) && is_string($response['body'])
        ? $response['body']
        : '';
}

/** @param mixed $response @return mixed */
function wp_remote_retrieve_header($response, string $name)
{
    if (!is_array($response) || !isset($response['headers']) || !is_array($response['headers'])) {
        return '';
    }
    return $response['headers'][strtolower($name)] ?? '';
}

/** @param mixed $value @return string|false */
function wp_json_encode($value)
{
    return json_encode($value);
}

/** @param array<string, mixed> $args */
function register_rest_route(string $namespace, string $route, array $args): bool
{
    $GLOBALS['oauth_test_routes'][$namespace . $route] = $args;
    return true;
}

function current_user_can(string $capability): bool
{
    return $capability === 'manage_options';
}

function get_current_user_id(): int
{
    return 1;
}

/** @param mixed $value @return mixed */
function rest_ensure_response($value)
{
    return $value;
}

require dirname(__DIR__) . '/vendor/autoload.php';
require dirname(__DIR__) . '/src/autoload.php';
define('ABSPATH', dirname(__DIR__) . '/');
require dirname(__DIR__) . '/plugin.php';

function oauth_test_reset(): void
{
    $GLOBALS['oauth_test_options'] = [];
    $GLOBALS['oauth_test_transients'] = [];
    $GLOBALS['oauth_test_http_queue'] = [];
    $GLOBALS['oauth_test_routes'] = [];
    $GLOBALS['oauth_test_delete_failure'] = null;
    putenv('OPENAI_API_KEY');
}

/** @param mixed $actual @param mixed $expected */
function oauth_test_same($actual, $expected, string $message = ''): void
{
    if ($actual !== $expected) {
        throw new RuntimeException(
            ($message !== '' ? $message . ': ' : '')
            . 'expected ' . var_export($expected, true)
            . ', got ' . var_export($actual, true)
        );
    }
}

/** @param mixed $value */
function oauth_test_true($value, string $message = ''): void
{
    oauth_test_same((bool) $value, true, $message);
}

function oauth_test_jwt(array $claims): string
{
    $encode = static function (array $data): string {
        $json = json_encode($data);
        if (!is_string($json)) {
            throw new RuntimeException('JWT test data could not be encoded.');
        }
        return rtrim(strtr(base64_encode($json), '+/', '-_'), '=');
    };

    return $encode(['alg' => 'none', 'typ' => 'JWT']) . '.' . $encode($claims) . '.signature';
}

/** @return array<string, mixed> */
function oauth_test_tokens(int $expiresAt, string $accessToken = ''): array
{
    if ($accessToken === '') {
        $accessToken = oauth_test_jwt([
            'exp' => $expiresAt,
            'email' => 'admin@example.com',
            'https://api.openai.com/auth' => ['chatgpt_account_id' => 'account-123'],
        ]);
    }

    return [
        'access_token' => $accessToken,
        'refresh_token' => 'refresh-token-one',
        'token_type' => 'Bearer',
        'expires_at' => $expiresAt,
        'obtained_at' => time(),
        'account_id' => 'account-123',
        'account_label' => 'admin@example.com',
    ];
}

/** @return array<string, mixed> */
function oauth_test_http_response(int $status, array $body, array $headers = []): array
{
    return [
        'response' => ['code' => $status],
        'headers' => $headers,
        'body' => json_encode($body),
    ];
}

function oauth_test_sse(bool $includeTerminal = true, bool $toolCall = false): string
{
    $item = $toolCall
        ? [
            'type' => 'function_call',
            'call_id' => 'call-1',
            'name' => 'lookup_weather',
            'arguments' => '{"city":"Douglas"}',
        ]
        : [
            'type' => 'message',
            'role' => 'assistant',
            'status' => 'completed',
            'content' => [['type' => 'output_text', 'text' => 'Hello from Codex']],
        ];
    $events = [
        ['type' => 'response.output_item.done', 'item' => $item],
    ];
    if ($includeTerminal) {
        $events[] = [
            'type' => 'response.completed',
            'response' => [
                'id' => 'response-1',
                'status' => 'completed',
                'usage' => ['input_tokens' => 2, 'output_tokens' => 3, 'total_tokens' => 5],
            ],
        ];
    }

    $body = '';
    foreach ($events as $event) {
        $body .= 'data: ' . json_encode($event) . "\n\n";
    }
    return $body . "data: [DONE]\n\n";
}

$tests = [];

$tests['encrypted storage and verified deletion'] = static function (): void {
    oauth_test_reset();
    $store = new EncryptedTokenStore();
    $tokens = oauth_test_tokens(time() + 3600);
    oauth_test_same($store->saveTokens($tokens), true);
    $stored = get_option(EncryptedTokenStore::OPTION_NAME, '');
    oauth_test_true(is_string($stored) && strpos($stored, 'refresh-token-one') === false);
    oauth_test_same($store->getTokens(), $tokens);

    $GLOBALS['oauth_test_delete_failure'] = EncryptedTokenStore::OPTION_NAME;
    $failed = $store->deleteTokens();
    oauth_test_true(OAuthError::is($failed));
    oauth_test_same(OAuthError::code($failed), 'oauth_token_deletion_failed');

    $GLOBALS['oauth_test_delete_failure'] = null;
    oauth_test_same($store->deleteTokens(), true);
    oauth_test_same(get_option(EncryptedTokenStore::OPTION_NAME, null), null);
};

$tests['token normalization and refresh rotation'] = static function (): void {
    oauth_test_reset();
    $client = new OAuthClient();
    $expiresAt = time() + 3600;
    $accessToken = oauth_test_jwt([
        'exp' => $expiresAt,
        'email' => 'owner@example.com',
        'https://api.openai.com/auth' => ['chatgpt_account_id' => 'account-456'],
    ]);
    $normalized = $client->tokenSetFromPayload([
        'access_token' => $accessToken,
        'refresh_token' => 'refresh-one',
    ]);
    oauth_test_true(is_array($normalized));
    oauth_test_same($normalized['expires_at'], $expiresAt);
    oauth_test_same($normalized['account_id'], 'account-456');

    $store = new EncryptedTokenStore();
    oauth_test_same($store->saveTokens(oauth_test_tokens(time() + 60)), true);
    $newAccessToken = oauth_test_jwt(['exp' => time() + 7200]);
    $GLOBALS['oauth_test_http_queue'][] = oauth_test_http_response(200, [
        'access_token' => $newAccessToken,
        'refresh_token' => 'refresh-token-two',
    ]);
    $manager = new OAuthTokenManager($store, $client);
    oauth_test_same($manager->getAccessToken(), $newAccessToken);
    $saved = $store->getTokens();
    oauth_test_true(is_array($saved));
    oauth_test_same($saved['refresh_token'], 'refresh-token-two');
};

$tests['transient refresh failure uses still-valid token'] = static function (): void {
    oauth_test_reset();
    $store = new EncryptedTokenStore();
    $tokens = oauth_test_tokens(time() + 60);
    oauth_test_same($store->saveTokens($tokens), true);
    $GLOBALS['oauth_test_http_queue'][] = new WP_Error('http_request_failed', 'Temporary network failure.');
    $manager = new OAuthTokenManager($store, new OAuthClient());
    oauth_test_same($manager->getAccessToken(), $tokens['access_token']);
};

$tests['device session cadence and cancellation'] = static function (): void {
    oauth_test_reset();
    $sessions = new OAuthSessionStore();
    $created = $sessions->create(1, [
        'device_auth_id' => 'device-1',
        'user_code' => 'ABCD-EFGH',
        'verification_url' => 'https://auth.openai.com/codex/device',
        'interval' => 3,
    ]);
    oauth_test_true(is_array($created));
    $sessionId = $created['session_id'];
    oauth_test_true(is_string($sessionId) && preg_match('/^[a-f0-9]{48}$/', $sessionId) === 1);

    $tooSoon = $sessions->beginPoll(1, $sessionId);
    oauth_test_same(OAuthError::code($tooSoon), 'oauth_poll_too_soon');

    $transientName = '_ai_openai_oauth_session_1';
    $GLOBALS['oauth_test_transients'][$transientName]['next_poll_at'] = time() - 1;
    oauth_test_true(is_array($sessions->beginPoll(1, $sessionId)));
    oauth_test_same($sessions->cancel(1, $sessionId), true);
    oauth_test_same(OAuthError::code($sessions->assertActive(1, $sessionId)), 'oauth_session_cancelled');
};

$tests['degraded status remains recoverable'] = static function (): void {
    oauth_test_reset();
    update_option(EncryptedTokenStore::OPTION_NAME, '{"version":1,"broken":true}', false);
    update_option(AuthenticationMode::OPTION_NAME, AuthenticationMode::MODE_OAUTH, false);
    $flow = new OAuthFlow();
    $status = $flow->status(1);
    oauth_test_true(is_array($status));
    oauth_test_same($status['mode'], AuthenticationMode::MODE_OAUTH);
    oauth_test_same($status['oauth_connected'], false);
    oauth_test_same($status['oauth_error_code'], 'oauth_token_storage_invalid');

    $controllerStatus = (new OAuthRestController($flow))->getStatus();
    oauth_test_true(is_array($controllerStatus));
    oauth_test_same($controllerStatus['oauth']['errorCode'], 'oauth_token_storage_invalid');
    oauth_test_same($flow->disconnect(1)['mode'], AuthenticationMode::MODE_API_KEY);
    oauth_test_same(get_option(EncryptedTokenStore::OPTION_NAME, null), null);
};

$tests['mode changes share the credential lock'] = static function (): void {
    oauth_test_reset();
    $store = new EncryptedTokenStore();
    oauth_test_same($store->saveTokens(oauth_test_tokens(time() + 3600)), true);
    add_option(
        '_ai_provider_for_openai_oauth_refresh_lock',
        ['owner' => 'another-request', 'expires_at' => time() + 30],
        '',
        false
    );
    $result = (new OAuthFlow())->setMode(1, AuthenticationMode::MODE_OAUTH);
    oauth_test_same(OAuthError::code($result), 'oauth_operation_locked');
};

$tests['REST route contract stays token-free'] = static function (): void {
    oauth_test_reset();
    (new OAuthRestController())->registerRoutes();
    $expected = [
        'ai-provider-for-openai/v1/auth/status' => 'GET',
        'ai-provider-for-openai/v1/auth/mode' => 'POST',
        'ai-provider-for-openai/v1/oauth/start' => 'POST',
        'ai-provider-for-openai/v1/oauth/poll' => 'POST',
        'ai-provider-for-openai/v1/oauth/cancel' => 'POST',
        'ai-provider-for-openai/v1/oauth/connection' => 'DELETE',
    ];
    foreach ($expected as $route => $method) {
        oauth_test_true(isset($GLOBALS['oauth_test_routes'][$route]), 'Missing route ' . $route);
        oauth_test_same($GLOBALS['oauth_test_routes'][$route]['methods'], $method);
    }
};

$tests['connector UI uses registered WordPress module dependencies'] = static function (): void {
    $plugin = file_get_contents(dirname(__DIR__) . '/plugin.php');
    $script = file_get_contents(dirname(__DIR__) . '/assets/js/openai-oauth-connector.js');
    oauth_test_true(is_string($plugin));
    oauth_test_true(is_string($script));
    oauth_test_true(strpos($plugin, "['id' => '@wordpress/connectors'") !== false);
    oauth_test_true(strpos($plugin, "['id' => '@wordpress/components'") === false);
    oauth_test_true(strpos($plugin, "['id' => '@wordpress/i18n'") === false);
    foreach (['wp-components', 'wp-element', 'wp-i18n', 'wp-api-fetch'] as $handle) {
        oauth_test_true(
            strpos($plugin, "wp_enqueue_script('{$handle}')") !== false,
            "Missing classic script dependency {$handle}."
        );
    }
    oauth_test_true(strpos($script, "from '@wordpress/connectors'") !== false);
    oauth_test_true(strpos($script, "from '@wordpress/components'") === false);
    oauth_test_true(strpos($script, "from '@wordpress/i18n'") === false);
};

$tests['OAuth credentials and model options are visible to integrations'] = static function (): void {
    oauth_test_reset();
    oauth_test_same(
        \WordPress\OpenAiAiProvider\include_oauth_credentials(false),
        false
    );

    $store = new EncryptedTokenStore();
    oauth_test_same($store->saveTokens(oauth_test_tokens(time() + 3600)), true);
    oauth_test_same(
        (new AuthenticationMode($store))->set(AuthenticationMode::MODE_OAUTH),
        true
    );
    oauth_test_same(
        \WordPress\OpenAiAiProvider\include_oauth_credentials(false),
        true
    );
    oauth_test_same(
        \WordPress\OpenAiAiProvider\include_oauth_credentials(true),
        true
    );
    oauth_test_true(isset($GLOBALS['oauth_test_filters']['wpai_has_ai_credentials']));

    $directory = new class extends OpenAiModelMetadataDirectory {
        /** @return list<\WordPress\AiClient\Providers\Models\DTO\ModelMetadata> */
        public function parseCodexResponse(Response $response): array
        {
            return $this->parseResponseToModelMetadataList($response);
        }
    };
    $directory->setRequestAuthentication(
        new OpenAiOAuthRequestAuthentication(new OAuthTokenManager($store, new OAuthClient()))
    );
    $models = $directory->parseCodexResponse(
        new Response(200, [], json_encode([
            'models' => [[
                'slug' => 'gpt-test',
                'display_name' => 'GPT Test',
                'visibility' => 'visible',
                'priority' => 1,
            ]],
        ]))
    );
    oauth_test_same(count($models), 1);
    $metadata = $models[0]->toArray();
    $optionNames = array_column($metadata['supportedOptions'], 'name');
    foreach (
        ['maxTokens', 'temperature', 'topP', 'outputMimeType', 'outputSchema', 'functionDeclarations']
        as $name
    ) {
        oauth_test_true(in_array($name, $optionNames, true), "Missing OAuth model option {$name}.");
    }
};

$tests['SSE parsing requires a terminal event and preserves tools'] = static function (): void {
    oauth_test_reset();
    $parsed = OpenAiCodexStreamResponseParser::parse(new Response(200, [], oauth_test_sse()));
    $data = $parsed->getData();
    oauth_test_same($data['id'], 'response-1');
    oauth_test_same($data['output'][0]['content'][0]['text'], 'Hello from Codex');

    $toolData = OpenAiCodexStreamResponseParser::parse(
        new Response(200, [], oauth_test_sse(true, true))
    )->getData();
    oauth_test_same($toolData['output'][0]['type'], 'function_call');
    oauth_test_same($toolData['output'][0]['call_id'], 'call-1');

    $thrown = false;
    try {
        OpenAiCodexStreamResponseParser::parse(new Response(200, [], oauth_test_sse(false)));
    } catch (Throwable $throwable) {
        $thrown = strpos($throwable->getMessage(), 'reported completion') !== false;
    }
    oauth_test_true($thrown, 'A truncated stream must throw.');
};

$tests['Codex tool schemas are sanitized without mutating input'] = static function (): void {
    oauth_test_reset();
    $tools = [[
        'type' => 'function',
        'name' => 'lookup',
        'parameters' => [
            'type' => 'object',
            'oneOf' => [['required' => ['email']]],
            'properties' => [
                'format' => ['type' => 'string', 'format' => 'email', 'pattern' => '.+@.+'],
                'model' => ['type' => 'string', 'enum' => ['openai/model', 'other/model']],
                'ref' => ['$ref' => '#/$defs/value', 'default' => null],
            ],
        ],
    ]];
    $sanitized = OpenAiCodexToolSchemaSanitizer::sanitize($tools);
    oauth_test_true(isset($tools[0]['parameters']['oneOf']), 'Input must not be mutated.');
    oauth_test_true(!isset($sanitized[0]['parameters']['oneOf']));
    oauth_test_true(isset($sanitized[0]['parameters']['properties']['format']));
    oauth_test_true(!isset($sanitized[0]['parameters']['properties']['format']['format']));
    oauth_test_true(!isset($sanitized[0]['parameters']['properties']['model']['enum']));
    oauth_test_true(!isset($sanitized[0]['parameters']['properties']['ref']['default']));
};

$tests['OAuth generation applies headers, routing, and timeout'] = static function (): void {
    oauth_test_reset();
    $store = new EncryptedTokenStore();
    $tokens = oauth_test_tokens(time() + 3600);
    oauth_test_same($store->saveTokens($tokens), true);

    $transporter = new class implements HttpTransporterInterface {
        /** @var Request|null */
        public $request;

        public function send(Request $request, ?RequestOptions $options = null): Response
        {
            unset($options);
            $this->request = $request;
            return new Response(200, ['content-type' => ['text/event-stream']], oauth_test_sse());
        }
    };
    $model = new OpenAiTextGenerationModel(
        new ModelMetadata('gpt-test', 'GPT Test', [CapabilityEnum::textGeneration()], []),
        new ProviderMetadata('openai', 'OpenAI', ProviderTypeEnum::cloud())
    );
    $model->setHttpTransporter($transporter);
    $model->setRequestAuthentication(
        new OpenAiOAuthRequestAuthentication(new OAuthTokenManager($store, new OAuthClient()))
    );
    $result = $model->generateTextResult([
        new Message(MessageRoleEnum::user(), [new MessagePart('Hello')]),
    ]);
    oauth_test_true($result->getCandidates() !== []);
    oauth_test_true($transporter->request instanceof Request);
    oauth_test_same($transporter->request->getUri(), 'https://chatgpt.com/backend-api/codex/responses');
    oauth_test_same($transporter->request->getHeaderAsString('originator'), 'codex_cli_rs');
    oauth_test_same($transporter->request->getHeaderAsString('ChatGPT-Account-ID'), 'account-123');
    oauth_test_same($transporter->request->getOptions()->getTimeout(), 120.0);
};

$failures = [];
foreach ($tests as $name => $test) {
    try {
        $test();
        fwrite(STDOUT, "PASS {$name}\n");
    } catch (Throwable $throwable) {
        $failures[] = $name . ': ' . $throwable->getMessage();
        fwrite(STDERR, "FAIL {$name}: {$throwable->getMessage()}\n");
    }
}

if ($failures) {
    exit(1);
}

fwrite(STDOUT, sprintf("%d OAuth regression tests passed.\n", count($tests)));
