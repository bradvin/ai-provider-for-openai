<?php

declare(strict_types=1);

// Standalone contract tests necessarily declare symbols and execute a runner.
// phpcs:disable PSR1.Classes.ClassDeclaration.MissingNamespace
// phpcs:disable PSR1.Classes.ClassDeclaration.MultipleClasses
// phpcs:disable PSR1.Files.SideEffects.FoundWithSymbols

use WordPress\AiClient\Common\Exception\RuntimeException as AiRuntimeException;
use WordPress\AiClient\Messages\DTO\Message;
use WordPress\AiClient\Messages\DTO\MessagePart;
use WordPress\AiClient\Messages\Enums\MessageRoleEnum;
use WordPress\AiClient\Providers\DTO\ProviderMetadata;
use WordPress\AiClient\Providers\Enums\ProviderTypeEnum;
use WordPress\AiClient\Providers\Http\Contracts\HttpTransporterInterface;
use WordPress\AiClient\Providers\Http\DTO\ApiKeyRequestAuthentication;
use WordPress\AiClient\Providers\Http\DTO\Request;
use WordPress\AiClient\Providers\Http\DTO\RequestOptions;
use WordPress\AiClient\Providers\Http\DTO\Response;
use WordPress\AiClient\Providers\Http\Enums\HttpMethodEnum;
use WordPress\AiClient\Providers\Models\DTO\ModelMetadata;
use WordPress\AiClient\Providers\Models\Enums\CapabilityEnum;
use WordPress\AiClient\Providers\ProviderRegistry;
use WordPress\OpenAiAiProvider\Admin\OAuthRestController;
use WordPress\OpenAiAiProvider\Authentication\AuthenticationMode;
use WordPress\OpenAiAiProvider\Authentication\EncryptedTokenStore;
use WordPress\OpenAiAiProvider\Authentication\OAuthClient;
use WordPress\OpenAiAiProvider\Authentication\OAuthError;
use WordPress\OpenAiAiProvider\Authentication\OAuthFlow;
use WordPress\OpenAiAiProvider\Authentication\OAuthSessionStore;
use WordPress\OpenAiAiProvider\Authentication\OAuthTokenManager;
use WordPress\OpenAiAiProvider\Authentication\OpenAiApiProfileRequestAuthenticationAdapter;
use WordPress\OpenAiAiProvider\Authentication\OpenAiOAuthRequestAuthentication;
use WordPress\OpenAiAiProvider\Contracts\OpenAiApiProfileAwareAuthenticationInterface;
use WordPress\OpenAiAiProvider\Contracts\OpenAiApiProfileInterface;
use WordPress\OpenAiAiProvider\Metadata\OpenAiModelMetadataDirectory;
use WordPress\OpenAiAiProvider\Models\OpenAiCodexStreamResponseParser;
use WordPress\OpenAiAiProvider\Models\OpenAiCodexToolSchemaSanitizer;
use WordPress\OpenAiAiProvider\Models\OpenAiImageGenerationModel;
use WordPress\OpenAiAiProvider\Models\OpenAiTextGenerationModel;
use WordPress\OpenAiAiProvider\Profiles\OpenAiCodexApiProfile;
use WordPress\OpenAiAiProvider\Provider\OpenAiApiOperation;
use WordPress\OpenAiAiProvider\Provider\OpenAiApiProfileResolver;
use WordPress\OpenAiAiProvider\Provider\OpenAiProvider;

/** @var array<string, list<callable>> */
$GLOBALS['openai_profile_test_filters'] = [];

/**
 * Minimal WordPress filter implementation for resolver contract tests.
 *
 * @param mixed $value The value being filtered.
 * @param mixed ...$args Additional filter arguments.
 * @return mixed The filtered value.
 */
function apply_filters(string $hookName, $value, ...$args)
{
    $callbacks = array_merge(
        $GLOBALS['oauth_test_filters'][$hookName] ?? [],
        $GLOBALS['openai_profile_test_filters'][$hookName] ?? []
    );
    foreach ($callbacks as $callback) {
        $value = $callback($value, ...$args);
    }

    return $value;
}

// WordPress's legacy error class intentionally uses its established API names.
// phpcs:disable Squiz.Classes.ValidClassName.NotPascalCase
// phpcs:disable PSR1.Methods.CamelCapsMethodName.NotCamelCaps
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
// phpcs:enable PSR1.Methods.CamelCapsMethodName.NotCamelCaps
// phpcs:enable Squiz.Classes.ValidClassName.NotPascalCase

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

/**
 * Shared event trace for request-order assertions.
 */
final class OpenAiProfileTestTrace
{
    /** @var list<string> */
    public array $events = [];
}

/**
 * Configurable alternate API profile used by the contract tests.
 */
final class OpenAiProfileTestProfile implements OpenAiApiProfileInterface
{
    private string $baseUrl;
    private string $cacheKey;

    /** @var list<ModelMetadata>|null */
    private ?array $parsedModels = null;

    /** @var list<string> */
    private array $supportedOperations;

    private bool $cacheKeyFailure = false;
    private ?Response $normalizedResponse = null;
    private ?string $normalizedText = null;
    private OpenAiProfileTestTrace $trace;

    /** @var list<array{defaultUrl: string, path: string, operation: string}> */
    public array $urlCalls = [];

    /**
     * @param list<string> $supportedOperations Supported operation identifiers.
     */
    public function __construct(
        string $cacheKey,
        array $supportedOperations,
        OpenAiProfileTestTrace $trace,
        string $baseUrl = 'https://profile.example/v1'
    ) {
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->cacheKey = $cacheKey;
        $this->supportedOperations = $supportedOperations;
        $this->trace = $trace;
    }

    public function getCacheKey(): string
    {
        if ($this->cacheKeyFailure) {
            throw new \RuntimeException('The profile cache identity is unavailable.');
        }

        return $this->cacheKey;
    }

    public function supportsOperation(string $operation): bool
    {
        return in_array($operation, $this->supportedOperations, true);
    }

    public function getRequestUrl(
        string $defaultUrl,
        string $path,
        string $operation
    ): string {
        $this->urlCalls[] = [
            'defaultUrl' => $defaultUrl,
            'path' => $path,
            'operation' => $operation,
        ];
        $this->trace->events[] = 'url:' . $operation;

        return $this->baseUrl . '/' . ltrim($path, '/');
    }

    public function prepareRequest(Request $request, string $operation): Request
    {
        $this->trace->events[] = 'prepare:' . $operation;

        return $request->withHeader('X-Profile-Prepared', $operation);
    }

    public function normalizeResponse(Response $response, string $operation): Response
    {
        $this->trace->events[] = 'normalize:' . $operation;
        if ($this->normalizedResponse !== null) {
            return $this->normalizedResponse;
        }
        if ($this->normalizedText === null) {
            return $response;
        }

        return openai_profile_test_text_response($this->normalizedText);
    }

    public function parseModelMetadataList(Response $response): ?array
    {
        unset($response);
        $this->trace->events[] = 'parse-models';

        return $this->parsedModels;
    }

    /**
     * Supplies metadata returned by parseModelMetadataList().
     *
     * @param list<ModelMetadata> $models Model metadata list.
     */
    public function setParsedModels(array $models): void
    {
        $this->parsedModels = $models;
    }

    /**
     * Makes normalizeResponse() return a standard Responses API payload.
     */
    public function setNormalizedText(string $text): void
    {
        $this->normalizedText = $text;
    }

    /**
     * Makes normalizeResponse() return a specific response.
     */
    public function setNormalizedResponse(Response $response): void
    {
        $this->normalizedResponse = $response;
    }

    /**
     * Makes getCacheKey() fail for fail-closed cache tests.
     */
    public function failCacheKeyLookup(): void
    {
        $this->cacheKeyFailure = true;
    }
}

/**
 * Authentication carrying a profile, with an assertion that preparation ran first.
 */
final class OpenAiProfileTestAuthentication extends ApiKeyRequestAuthentication implements
    OpenAiApiProfileAwareAuthenticationInterface
{
    private OpenAiApiProfileInterface $profile;
    private OpenAiProfileTestTrace $trace;

    public int $profileResolutionCount = 0;

    public function __construct(
        OpenAiApiProfileInterface $profile,
        OpenAiProfileTestTrace $trace,
        string $apiKey = 'profile-test-key'
    ) {
        parent::__construct($apiKey);
        $this->profile = $profile;
        $this->trace = $trace;
    }

    public function getOpenAiApiProfile(): OpenAiApiProfileInterface
    {
        $this->profileResolutionCount++;

        return $this->profile;
    }

    public function authenticateRequest(Request $request): Request
    {
        if (!$request->hasHeader('X-Profile-Prepared')) {
            throw new \RuntimeException('The profile request was not prepared before authentication.');
        }

        $this->trace->events[] = 'authenticate';

        return parent::authenticateRequest($request);
    }
}

/**
 * Profile-aware authentication that is intentionally unrelated to API keys.
 */
final class OpenAiProfileTestDelegatedAuthentication implements
    OpenAiApiProfileAwareAuthenticationInterface
{
    private OpenAiApiProfileInterface $profile;

    public function __construct(OpenAiApiProfileInterface $profile)
    {
        $this->profile = $profile;
    }

    public function getOpenAiApiProfile(): OpenAiApiProfileInterface
    {
        return $this->profile;
    }

    public function authenticateRequest(Request $request): Request
    {
        return $request->withHeader('Authorization', 'Bearer delegated-profile-token');
    }

    /** @return array<string, mixed> */
    public static function getJsonSchema(): array
    {
        return ['type' => 'object', 'properties' => []];
    }
}

/**
 * Capturing HTTP transporter for request and short-circuit assertions.
 */
final class OpenAiProfileTestTransporter implements HttpTransporterInterface
{
    public ?Request $request = null;
    public int $sendCount = 0;

    private Response $response;
    private ?OpenAiProfileTestTrace $trace;

    public function __construct(Response $response, ?OpenAiProfileTestTrace $trace = null)
    {
        $this->response = $response;
        $this->trace = $trace;
    }

    public function send(Request $request, ?RequestOptions $options = null): Response
    {
        unset($options);
        $this->request = $request;
        $this->sendCount++;
        if ($this->trace !== null) {
            $this->trace->events[] = 'transport';
        }

        return $this->response;
    }
}

/**
 * Exposes the protected cache prefix for isolation contract tests.
 */
final class OpenAiProfileTestMetadataDirectory extends OpenAiModelMetadataDirectory
{
    public function baseCacheKey(): string
    {
        return $this->getBaseCacheKey();
    }
}

/**
 * Resets global test state between contract tests.
 */
function openai_profile_test_reset(): void
{
    $GLOBALS['openai_profile_test_filters'] = [];
}

/**
 * @param mixed $actual Actual value.
 * @param mixed $expected Expected value.
 */
function openai_profile_test_same($actual, $expected, string $message = ''): void
{
    if ($actual === $expected) {
        return;
    }

    throw new \RuntimeException(
        ($message !== '' ? $message . ': ' : '')
        . 'expected ' . var_export($expected, true)
        . ', got ' . var_export($actual, true)
    );
}

/**
 * @param mixed $value Value expected to be truthy.
 */
function openai_profile_test_true($value, string $message = ''): void
{
    openai_profile_test_same((bool) $value, true, $message);
}

/**
 * Creates metadata for a test model.
 *
 * @param object $capability Capability enum value.
 */
function openai_profile_test_model_metadata(string $id, $capability): ModelMetadata
{
    return new ModelMetadata($id, $id, [$capability], []);
}

/**
 * Creates provider metadata for a test model.
 */
function openai_profile_test_provider_metadata(): ProviderMetadata
{
    return new ProviderMetadata('openai', 'OpenAI', ProviderTypeEnum::cloud());
}

/**
 * Creates a successful standard Responses API response.
 */
function openai_profile_test_text_response(string $text): Response
{
    $body = json_encode([
        'id' => 'response-contract-test',
        'status' => 'completed',
        'output' => [
            [
                'type' => 'message',
                'role' => 'assistant',
                'status' => 'completed',
                'content' => [
                    [
                        'type' => 'output_text',
                        'text' => $text,
                    ],
                ],
            ],
        ],
        'usage' => [
            'input_tokens' => 2,
            'output_tokens' => 3,
            'total_tokens' => 5,
        ],
    ]);
    if (!is_string($body)) {
        throw new \RuntimeException('The test response could not be encoded.');
    }

    return new Response(200, ['Content-Type' => 'application/json'], $body);
}

/**
 * Creates a successful standard Images API response.
 */
function openai_profile_test_image_response(string $imageData): Response
{
    $body = json_encode([
        'created' => 1234567890,
        'data' => [
            ['b64_json' => base64_encode($imageData)],
        ],
        'usage' => [
            'input_tokens' => 1,
            'output_tokens' => 2,
            'total_tokens' => 3,
        ],
    ]);
    if (!is_string($body)) {
        throw new \RuntimeException('The test image response could not be encoded.');
    }

    return new Response(200, ['Content-Type' => 'application/json'], $body);
}

/**
 * Creates a simple user prompt.
 *
 * @return list<Message>
 */
function openai_profile_test_prompt(): array
{
    return [new Message(MessageRoleEnum::user(), [new MessagePart('Hello')])];
}

/** @var array<string, callable> $tests */
$tests = [];

$tests['profile authentication adapter satisfies the registry type contract'] = static function (): void {
    openai_profile_test_reset();
    $profile = new OpenAiProfileTestProfile(
        'profile-adapter',
        [OpenAiApiOperation::GENERATE_TEXT],
        new OpenAiProfileTestTrace()
    );
    $delegate = new OpenAiProfileTestDelegatedAuthentication($profile);
    $authentication = new OpenAiApiProfileRequestAuthenticationAdapter($delegate);

    openai_profile_test_true($authentication instanceof ApiKeyRequestAuthentication);
    openai_profile_test_same(
        OpenAiApiProfileResolver::resolve($authentication),
        $profile
    );

    $request = new Request(
        \WordPress\AiClient\Providers\Http\Enums\HttpMethodEnum::GET(),
        'https://profile-adapter.example/models'
    );
    $authenticatedRequest = $authentication->authenticateRequest($request);
    openai_profile_test_same(
        $authenticatedRequest->getHeaderAsString('Authorization'),
        'Bearer delegated-profile-token'
    );
    openai_profile_test_same(
        strpos($authenticatedRequest->getHeaderAsString('Authorization'), 'managed-authentication'),
        false
    );

    $registry = new ProviderRegistry();
    $registry->registerProvider(OpenAiProvider::class);
    try {
        $registry->setProviderRequestAuthentication(OpenAiProvider::class, $authentication);
        openai_profile_test_same(
            $registry->getProviderRequestAuthentication(OpenAiProvider::class),
            $authentication
        );
        openai_profile_test_same(
            OpenAiProvider::modelMetadataDirectory()->getRequestAuthentication(),
            $authentication
        );
    } finally {
        $registry->setProviderRequestAuthentication(
            OpenAiProvider::class,
            new ApiKeyRequestAuthentication('profile-adapter-test-reset-key')
        );
    }
};

$tests['plain API-key behavior remains unchanged'] = static function (): void {
    openai_profile_test_reset();
    $authentication = new ApiKeyRequestAuthentication('standard-api-key');
    openai_profile_test_same(OpenAiApiProfileResolver::resolve($authentication), null);

    $transporter = new OpenAiProfileTestTransporter(
        openai_profile_test_text_response('Standard API response')
    );
    $model = new OpenAiTextGenerationModel(
        openai_profile_test_model_metadata('gpt-standard', CapabilityEnum::textGeneration()),
        openai_profile_test_provider_metadata()
    );
    $model->setRequestAuthentication($authentication);
    $model->setHttpTransporter($transporter);

    $result = $model->generateTextResult(openai_profile_test_prompt());
    openai_profile_test_same($result->toText(), 'Standard API response');
    openai_profile_test_same($transporter->sendCount, 1);
    openai_profile_test_true($transporter->request instanceof Request);
    openai_profile_test_same(
        $transporter->request->getUri(),
        'https://api.openai.com/v1/responses'
    );
    openai_profile_test_same(
        $transporter->request->getHeaderAsString('Authorization'),
        'Bearer standard-api-key'
    );
    openai_profile_test_same($transporter->request->hasHeader('X-Profile-Prepared'), false);

    $requestData = $transporter->request->getData();
    openai_profile_test_true(is_array($requestData));
    openai_profile_test_same($requestData['model'] ?? null, 'gpt-standard');
    openai_profile_test_true(isset($requestData['input']));
};

$tests['profile prepares before auth and normalizes successful response'] = static function (): void {
    openai_profile_test_reset();
    $trace = new OpenAiProfileTestTrace();
    $profile = new OpenAiProfileTestProfile(
        'profile-text',
        [OpenAiApiOperation::GENERATE_TEXT],
        $trace
    );
    $profile->setNormalizedText('Normalized profile response');
    $authentication = new OpenAiProfileTestAuthentication($profile, $trace);
    $rawResponse = new Response(
        200,
        ['Content-Type' => 'application/x-profile-response'],
        '{"alternateText":"raw"}'
    );
    $transporter = new OpenAiProfileTestTransporter($rawResponse, $trace);
    $model = new OpenAiTextGenerationModel(
        openai_profile_test_model_metadata('gpt-profile', CapabilityEnum::textGeneration()),
        openai_profile_test_provider_metadata()
    );
    $model->setRequestAuthentication($authentication);
    $model->setHttpTransporter($transporter);

    $result = $model->generateTextResult(openai_profile_test_prompt());
    openai_profile_test_same($result->toText(), 'Normalized profile response');
    openai_profile_test_same(
        $authentication->profileResolutionCount,
        1,
        'A text model must pin one profile for the bound authentication'
    );
    openai_profile_test_same(
        $trace->events,
        [
            'url:' . OpenAiApiOperation::GENERATE_TEXT,
            'prepare:' . OpenAiApiOperation::GENERATE_TEXT,
            'authenticate',
            'transport',
            'normalize:' . OpenAiApiOperation::GENERATE_TEXT,
        ]
    );
    openai_profile_test_same(
        $transporter->request instanceof Request ? $transporter->request->getUri() : '',
        'https://profile.example/v1/responses'
    );
    openai_profile_test_same(
        $transporter->request instanceof Request
            ? $transporter->request->getHeaderAsString('X-Profile-Prepared')
            : null,
        OpenAiApiOperation::GENERATE_TEXT
    );
    openai_profile_test_same(
        $profile->urlCalls,
        [[
            'defaultUrl' => 'https://api.openai.com/v1/responses',
            'path' => 'responses',
            'operation' => OpenAiApiOperation::GENERATE_TEXT,
        ]]
    );
};

$tests['alternate model catalog parsing and cache isolation'] = static function (): void {
    openai_profile_test_reset();
    $traceA = new OpenAiProfileTestTrace();
    $profileA = new OpenAiProfileTestProfile(
        'tenant-sensitive-value-alpha',
        [OpenAiApiOperation::LIST_MODELS],
        $traceA
    );
    $profileA->setParsedModels([
        openai_profile_test_model_metadata('profile-model', CapabilityEnum::textGeneration()),
    ]);
    $authenticationA = new OpenAiProfileTestAuthentication($profileA, $traceA);
    $directoryA = new OpenAiProfileTestMetadataDirectory();
    $transporterA = new OpenAiProfileTestTransporter(
        new Response(200, [], '{"profileModels":true}'),
        $traceA
    );
    $directoryA->setRequestAuthentication($authenticationA);
    $directoryA->setHttpTransporter($transporterA);

    $models = $directoryA->listModelMetadata();
    openai_profile_test_same(count($models), 1);
    openai_profile_test_same($models[0]->getId(), 'profile-model');
    openai_profile_test_same(
        $transporterA->request instanceof Request ? $transporterA->request->getUri() : '',
        'https://profile.example/v1/models'
    );
    openai_profile_test_true(in_array('parse-models', $traceA->events, true));

    $traceA2 = new OpenAiProfileTestTrace();
    $profileA2 = new OpenAiProfileTestProfile(
        'tenant-sensitive-value-alpha',
        [OpenAiApiOperation::LIST_MODELS],
        $traceA2
    );
    $directoryA2 = new OpenAiProfileTestMetadataDirectory();
    $directoryA2->setRequestAuthentication(
        new OpenAiProfileTestAuthentication($profileA2, $traceA2)
    );

    $traceB = new OpenAiProfileTestTrace();
    $profileB = new OpenAiProfileTestProfile(
        'tenant-sensitive-value-beta',
        [OpenAiApiOperation::LIST_MODELS],
        $traceB
    );
    $directoryB = new OpenAiProfileTestMetadataDirectory();
    $directoryB->setRequestAuthentication(
        new OpenAiProfileTestAuthentication($profileB, $traceB)
    );

    $directoryStandard = new OpenAiProfileTestMetadataDirectory();
    $directoryStandard->setRequestAuthentication(new ApiKeyRequestAuthentication('standard-key'));

    openai_profile_test_same($directoryA->baseCacheKey(), $directoryA2->baseCacheKey());
    openai_profile_test_true($directoryA->baseCacheKey() !== $directoryB->baseCacheKey());
    openai_profile_test_true($directoryA->baseCacheKey() !== $directoryStandard->baseCacheKey());
    openai_profile_test_same(
        strpos($directoryA->baseCacheKey(), 'tenant-sensitive-value-alpha'),
        false,
        'Profile cache identity must be hashed before entering the cache key'
    );
    openai_profile_test_same(
        $authenticationA->profileResolutionCount,
        1,
        'Catalog cache, request, and parsing must share one pinned profile'
    );
};

$tests['unsupported image operation fails before transport'] = static function (): void {
    openai_profile_test_reset();
    $trace = new OpenAiProfileTestTrace();
    $profile = new OpenAiProfileTestProfile(
        'text-only-profile',
        [OpenAiApiOperation::LIST_MODELS, OpenAiApiOperation::GENERATE_TEXT],
        $trace
    );
    $transporter = new OpenAiProfileTestTransporter(new Response(200, [], '{}'), $trace);
    $model = new OpenAiImageGenerationModel(
        openai_profile_test_model_metadata('image-profile', CapabilityEnum::imageGeneration()),
        openai_profile_test_provider_metadata()
    );
    $authentication = new OpenAiProfileTestAuthentication($profile, $trace);
    $model->setRequestAuthentication($authentication);
    $model->setHttpTransporter($transporter);

    $thrown = false;
    try {
        $model->generateImageResult(openai_profile_test_prompt());
    } catch (AiRuntimeException $exception) {
        $message = $exception->getMessage();
        $thrown = strpos($message, 'support') !== false
            && strpos($message, 'image generation') !== false;
    }

    openai_profile_test_true($thrown, 'Unsupported image generation must throw a runtime exception.');
    openai_profile_test_same($transporter->sendCount, 0, 'Unsupported operations must not reach transport.');
    openai_profile_test_same(in_array('authenticate', $trace->events, true), false);
    openai_profile_test_same($authentication->profileResolutionCount, 1);
};

$tests['profile-backed image lifecycle uses one pinned profile'] = static function (): void {
    openai_profile_test_reset();
    $trace = new OpenAiProfileTestTrace();
    $profile = new OpenAiProfileTestProfile(
        'profile-image',
        [OpenAiApiOperation::GENERATE_IMAGE],
        $trace
    );
    $profile->setNormalizedResponse(
        openai_profile_test_image_response('normalized-profile-image')
    );
    $authentication = new OpenAiProfileTestAuthentication($profile, $trace);
    $transporter = new OpenAiProfileTestTransporter(
        new Response(200, ['Content-Type' => 'application/x-profile-image'], '{"image":"raw"}'),
        $trace
    );
    $model = new OpenAiImageGenerationModel(
        openai_profile_test_model_metadata('gpt-image-profile', CapabilityEnum::imageGeneration()),
        openai_profile_test_provider_metadata()
    );
    $model->setRequestAuthentication($authentication);
    $model->setHttpTransporter($transporter);

    $result = $model->generateImageResult(openai_profile_test_prompt());
    openai_profile_test_same($result->getId(), 'img-1234567890');
    openai_profile_test_same(
        $result->toFile()->getBase64Data(),
        base64_encode('normalized-profile-image')
    );
    openai_profile_test_same($transporter->sendCount, 1);
    openai_profile_test_same($authentication->profileResolutionCount, 1);
    openai_profile_test_same(
        $trace->events,
        [
            'url:' . OpenAiApiOperation::GENERATE_IMAGE,
            'prepare:' . OpenAiApiOperation::GENERATE_IMAGE,
            'authenticate',
            'transport',
            'normalize:' . OpenAiApiOperation::GENERATE_IMAGE,
        ]
    );
    openai_profile_test_same(
        $transporter->request instanceof Request ? $transporter->request->getUri() : '',
        'https://profile.example/v1/images/generations'
    );
    openai_profile_test_same(
        $transporter->request instanceof Request
            ? $transporter->request->getHeaderAsString('X-Profile-Prepared')
            : null,
        OpenAiApiOperation::GENERATE_IMAGE
    );
    openai_profile_test_same(
        $profile->urlCalls,
        [[
            'defaultUrl' => 'https://api.openai.com/v1/images/generations',
            'path' => 'images/generations',
            'operation' => OpenAiApiOperation::GENERATE_IMAGE,
        ]]
    );
};

$tests['profile cache identity failures fail closed'] = static function (): void {
    openai_profile_test_reset();
    $trace = new OpenAiProfileTestTrace();
    $profile = new OpenAiProfileTestProfile(
        'must-not-be-shared',
        [OpenAiApiOperation::LIST_MODELS],
        $trace
    );
    $profile->failCacheKeyLookup();
    $authentication = new OpenAiProfileTestAuthentication($profile, $trace);
    $directory = new OpenAiProfileTestMetadataDirectory();
    $directory->setRequestAuthentication($authentication);

    $thrown = false;
    try {
        $directory->baseCacheKey();
    } catch (\RuntimeException $exception) {
        $thrown = strpos($exception->getMessage(), 'cache identity') !== false;
    }

    openai_profile_test_true(
        $thrown,
        'A profile cache identity failure must not fall back to a shared cache key'
    );
    openai_profile_test_same($authentication->profileResolutionCount, 1);
};

$tests['resolver filter accepts profiles and rejects invalid values'] = static function (): void {
    openai_profile_test_reset();
    $authentication = new ApiKeyRequestAuthentication('filter-test-key');
    $trace = new OpenAiProfileTestTrace();
    $filteredProfile = new OpenAiProfileTestProfile(
        'filtered-profile',
        [OpenAiApiOperation::GENERATE_TEXT],
        $trace
    );
    $filterSawAuthentication = false;
    $GLOBALS['openai_profile_test_filters']['ai_provider_for_openai_api_profile'][] =
        static function (
            $profile,
            $receivedAuthentication
        ) use (
            $authentication,
            $filteredProfile,
            &$filterSawAuthentication
        ) {
            openai_profile_test_same($profile, null);
            $filterSawAuthentication = $receivedAuthentication === $authentication;

            return $filteredProfile;
        };

    openai_profile_test_same(
        OpenAiApiProfileResolver::resolve($authentication),
        $filteredProfile
    );
    openai_profile_test_true($filterSawAuthentication, 'The resolver must pass authentication to the filter.');

    openai_profile_test_reset();
    $GLOBALS['openai_profile_test_filters']['ai_provider_for_openai_api_profile'][] =
        static function () {
            return new stdClass();
        };

    $thrown = false;
    try {
        OpenAiApiProfileResolver::resolve($authentication);
    } catch (AiRuntimeException $exception) {
        $thrown = strpos($exception->getMessage(), 'OpenAiApiProfileInterface') !== false;
    }
    openai_profile_test_true($thrown, 'Invalid filtered profiles must fail validation.');
};

define('ABSPATH', dirname(__DIR__) . '/');
require dirname(__DIR__) . '/plugin.php';

function oauth_test_reset(): void
{
    $GLOBALS['oauth_test_options'] = [];
    $GLOBALS['oauth_test_transients'] = [];
    $GLOBALS['oauth_test_http_queue'] = [];
    $GLOBALS['oauth_test_routes'] = [];
    $GLOBALS['oauth_test_delete_failure'] = null;
    $GLOBALS['openai_profile_test_filters'] = [];
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
    $oauthAuthentication = new OpenAiOAuthRequestAuthentication(
        new OAuthTokenManager($store, new OAuthClient())
    );
    oauth_test_true($oauthAuthentication instanceof OpenAiApiProfileAwareAuthenticationInterface);
    oauth_test_same($oauthAuthentication instanceof ApiKeyRequestAuthentication, false);
    $registryAuthentication = new OpenAiApiProfileRequestAuthenticationAdapter(
        $oauthAuthentication
    );
    oauth_test_true($registryAuthentication instanceof ApiKeyRequestAuthentication);
    oauth_test_same(
        $registryAuthentication->getOpenAiApiProfile(),
        $oauthAuthentication->getOpenAiApiProfile()
    );

    \WordPress\OpenAiAiProvider\register_provider();
    \WordPress\OpenAiAiProvider\configure_oauth_authentication();
    $registry = \WordPress\AiClient\AiClient::defaultRegistry();
    try {
        $configuredAuthentication = $registry->getProviderRequestAuthentication(
            OpenAiProvider::class
        );
        oauth_test_true(
            $configuredAuthentication instanceof OpenAiApiProfileRequestAuthenticationAdapter,
            'OAuth mode must install the registry compatibility adapter.'
        );
        oauth_test_true(
            OpenAiApiProfileResolver::resolve($configuredAuthentication)
                instanceof OpenAiCodexApiProfile
        );
    } finally {
        $registry->setProviderRequestAuthentication(
            OpenAiProvider::class,
            new ApiKeyRequestAuthentication('oauth-registry-test-reset-key')
        );
    }

    $codexProfile = $oauthAuthentication->getOpenAiApiProfile();
    oauth_test_true($codexProfile instanceof OpenAiCodexApiProfile);
    oauth_test_same($codexProfile->supportsOperation(OpenAiApiOperation::LIST_MODELS), true);
    oauth_test_same($codexProfile->supportsOperation(OpenAiApiOperation::GENERATE_TEXT), true);
    oauth_test_same($codexProfile->supportsOperation(OpenAiApiOperation::GENERATE_IMAGE), false);
    oauth_test_same($codexProfile->supportsOperation(OpenAiApiOperation::EDIT_IMAGE), false);
    oauth_test_same(
        $oauthAuthentication->getCacheKeySuffix(),
        $codexProfile->getAccountCacheSuffix()
    );
    $authenticationSchema = OpenAiOAuthRequestAuthentication::getJsonSchema();
    oauth_test_same($authenticationSchema['type'] ?? null, 'object');
    oauth_test_same($authenticationSchema['properties'] ?? null, []);
    oauth_test_same($authenticationSchema['additionalProperties'] ?? null, false);
    oauth_test_true(is_string($authenticationSchema['title'] ?? null));
    oauth_test_true(is_string($authenticationSchema['description'] ?? null));
    $directory->setRequestAuthentication($oauthAuthentication);
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
    $expectedOptionNames = [
        'maxTokens',
        'temperature',
        'topP',
        'outputMimeType',
        'outputSchema',
        'functionDeclarations',
    ];
    foreach ($expectedOptionNames as $name) {
        oauth_test_true(in_array($name, $optionNames, true), "Missing OAuth model option {$name}.");
    }

    $profileIntegratedFiles = [
        'src/Metadata/OpenAiModelMetadataDirectory.php',
        'src/Models/OpenAiTextGenerationModel.php',
        'src/Models/OpenAiImageGenerationModel.php',
    ];
    foreach ($profileIntegratedFiles as $relativePath) {
        $source = file_get_contents(dirname(__DIR__) . '/' . $relativePath);
        oauth_test_true(is_string($source));
        oauth_test_same(strpos($source, 'OpenAiOAuthRequestAuthentication'), false);
        oauth_test_same(strpos($source, 'OpenAiCodexApiProfile'), false);
    }
};

$tests['OAuth bearer authentication rejects rerouted requests before token lookup'] = static function (): void {
    oauth_test_reset();
    $authentication = new OpenAiOAuthRequestAuthentication(new OAuthTokenManager());
    $request = new Request(
        HttpMethodEnum::POST(),
        'https://attacker.example/backend-api/codex/responses',
        ['Content-Type' => 'application/json'],
        []
    );

    $thrown = false;
    try {
        $authentication->authenticateRequest($request);
    } catch (AiRuntimeException $exception) {
        $message = strtolower($exception->getMessage());
        $thrown = strpos($message, 'codex') !== false
            && strpos($message, 'credential') !== false;
    }

    oauth_test_true(
        $thrown,
        'The final request URI must be rejected before missing credentials are read'
    );
    oauth_test_same($request->getHeaderAsString('Authorization'), null);
};

$tests['OAuth model cache identities are account-specific and never shared'] = static function (): void {
    oauth_test_reset();
    $store = new EncryptedTokenStore();
    $tokensA = oauth_test_tokens(time() + 3600);
    oauth_test_same($store->saveTokens($tokensA), true);
    $suffixA = (new OpenAiOAuthRequestAuthentication(
        new OAuthTokenManager($store, new OAuthClient())
    ))->getCacheKeySuffix();

    $tokensB = oauth_test_tokens(time() + 3600);
    $tokensB['account_id'] = 'account-456';
    oauth_test_same($store->saveTokens($tokensB), true);
    $suffixB = (new OpenAiOAuthRequestAuthentication(
        new OAuthTokenManager($store, new OAuthClient())
    ))->getCacheKeySuffix();

    oauth_test_true(preg_match('/\Aoauth_[a-f0-9]{32}\z/', $suffixA) === 1);
    oauth_test_true(preg_match('/\Aoauth_[a-f0-9]{32}\z/', $suffixB) === 1);
    oauth_test_true($suffixA !== $suffixB);
    oauth_test_same(strpos($suffixA, 'account-123'), false);
    oauth_test_same(strpos($suffixB, 'account-456'), false);

    $tokensWithoutAccount = oauth_test_tokens(time() + 3600);
    unset($tokensWithoutAccount['account_id']);
    oauth_test_same($store->saveTokens($tokensWithoutAccount), true);
    $fallbackSuffix = (new OpenAiOAuthRequestAuthentication(
        new OAuthTokenManager($store, new OAuthClient())
    ))->getCacheKeySuffix();
    oauth_test_true(
        preg_match('/\Aoauth_token_[a-f0-9]{32}\z/', $fallbackSuffix) === 1
    );
    oauth_test_same($fallbackSuffix === 'oauth', false);
    oauth_test_same(strpos($fallbackSuffix, 'refresh-token-one'), false);

    oauth_test_reset();
    $missingIdentityThrew = false;
    try {
        (new OpenAiOAuthRequestAuthentication(new OAuthTokenManager()))->getCacheKeySuffix();
    } catch (AiRuntimeException $exception) {
        $missingIdentityThrew = strpos($exception->getMessage(), 'cache isolation') !== false;
    }
    oauth_test_true($missingIdentityThrew, 'Missing credentials must fail cache isolation closed.');
};

$tests['OAuth disconnect cache invalidation tolerates a missing identity'] = static function (): void {
    oauth_test_reset();
    $store = new EncryptedTokenStore();
    oauth_test_same($store->saveTokens(oauth_test_tokens(time() + 3600)), true);

    $directory = OpenAiProvider::modelMetadataDirectory();
    oauth_test_true($directory instanceof OpenAiModelMetadataDirectory);
    $directory->setRequestAuthentication(
        new OpenAiOAuthRequestAuthentication(
            new OAuthTokenManager($store, new OAuthClient())
        )
    );

    // Pin the account profile and prove its cache identity is available before disconnect.
    $directory->invalidateCaches();
    oauth_test_same($store->deleteTokens(), true);

    $caught = null;
    try {
        \WordPress\OpenAiAiProvider\invalidate_model_metadata_cache();
    } catch (Throwable $throwable) {
        $caught = $throwable;
    } finally {
        $directory->setRequestAuthentication(
            new ApiKeyRequestAuthentication('test-reset-key')
        );
    }

    oauth_test_same(
        $caught,
        null,
        'Best-effort cache invalidation must survive a missing OAuth cache identity.'
    );
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
    $oauthAuthentication = new OpenAiOAuthRequestAuthentication(
        new OAuthTokenManager($store, new OAuthClient())
    );
    $model->setRequestAuthentication($oauthAuthentication);
    $result = $model->generateTextResult([
        new Message(MessageRoleEnum::user(), [new MessagePart('Hello')]),
    ]);
    oauth_test_true($result->getCandidates() !== []);
    oauth_test_true($transporter->request instanceof Request);
    oauth_test_same($transporter->request->getUri(), 'https://chatgpt.com/backend-api/codex/responses');
    oauth_test_same($transporter->request->getHeaderAsString('originator'), 'codex_cli_rs');
    oauth_test_same($transporter->request->getHeaderAsString('ChatGPT-Account-ID'), 'account-123');
    oauth_test_same($transporter->request->getOptions()->getTimeout(), 120.0);
    oauth_test_true(
        $oauthAuthentication->getOpenAiApiProfile() instanceof OpenAiCodexApiProfile
    );
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

if ($failures !== []) {
    exit(1);
}

fwrite(STDOUT, sprintf("%d OpenAI provider regression tests passed.\n", count($tests)));
