<?php

declare(strict_types=1);

namespace WordPress\OpenAiAiProvider\Profiles;

use WordPress\AiClient\Common\Exception\RuntimeException;
use WordPress\AiClient\Messages\Enums\ModalityEnum;
use WordPress\AiClient\Providers\Http\DTO\Request;
use WordPress\AiClient\Providers\Http\DTO\RequestOptions;
use WordPress\AiClient\Providers\Http\DTO\Response;
use WordPress\AiClient\Providers\Http\Exception\ResponseException;
use WordPress\AiClient\Providers\Models\DTO\ModelMetadata;
use WordPress\AiClient\Providers\Models\DTO\SupportedOption;
use WordPress\AiClient\Providers\Models\Enums\CapabilityEnum;
use WordPress\AiClient\Providers\Models\Enums\OptionEnum;
use WordPress\OpenAiAiProvider\Authentication\OAuthConfig;
use WordPress\OpenAiAiProvider\Authentication\OAuthTokenManager;
use WordPress\OpenAiAiProvider\Contracts\OpenAiApiProfileInterface;
use WordPress\OpenAiAiProvider\Models\OpenAiCodexStreamResponseParser;
use WordPress\OpenAiAiProvider\Models\OpenAiCodexToolSchemaSanitizer;
use WordPress\OpenAiAiProvider\Provider\OpenAiApiOperation;

/**
 * OpenAI API profile for the account-backed Codex endpoint.
 *
 * @since 1.1.0
 *
 * @phpstan-type CodexModelData array{
 *     slug?: mixed,
 *     display_name?: mixed,
 *     visibility?: mixed,
 *     priority?: mixed
 * }
 * @phpstan-type CodexModelsResponseData array{
 *     models: list<CodexModelData>
 * }
 */
final class OpenAiCodexApiProfile implements OpenAiApiProfileInterface
{
    /**
     * The OAuth token manager used to identify the connected account.
     *
     * @var OAuthTokenManager
     */
    private OAuthTokenManager $tokenManager;

    /**
     * Constructor.
     *
     * @since 1.1.0
     *
     * @param OAuthTokenManager $tokenManager The OAuth token manager.
     */
    public function __construct(OAuthTokenManager $tokenManager)
    {
        $this->tokenManager = $tokenManager;
    }

    /**
     * {@inheritDoc}
     */
    public function getCacheKey(): string
    {
        return 'metadata_v3_' . $this->getAccountCacheSuffix();
    }

    /**
     * Gets a non-secret suffix for separating account model caches.
     *
     * @since 1.1.0
     *
     * @return string A stable cache suffix for the connected account.
     */
    public function getAccountCacheSuffix(): string
    {
        $tokens = $this->tokenManager->getStoredTokenSet();
        if (!is_array($tokens)) {
            throw new RuntimeException(
                'OpenAI account credentials are unavailable for model cache isolation.'
            );
        }

        $accountId = $tokens['account_id'] ?? '';
        if (is_string($accountId) && trim($accountId) !== '') {
            return 'oauth_' . substr(
                hash('sha256', 'account_id:' . trim($accountId)),
                0,
                32
            );
        }

        foreach (['refresh_token', 'access_token'] as $tokenKey) {
            $token = $tokens[$tokenKey] ?? '';
            if (is_string($token) && trim($token) !== '') {
                return 'oauth_token_' . substr(
                    hash('sha256', $tokenKey . ':' . trim($token)),
                    0,
                    32
                );
            }
        }

        throw new RuntimeException(
            'OpenAI account credentials do not contain a stable model cache identity.'
        );
    }

    /**
     * {@inheritDoc}
     */
    public function supportsOperation(string $operation): bool
    {
        return in_array(
            $operation,
            [
                OpenAiApiOperation::LIST_MODELS,
                OpenAiApiOperation::GENERATE_TEXT,
            ],
            true
        );
    }

    /**
     * {@inheritDoc}
     */
    public function getRequestUrl(
        string $defaultUrl,
        string $path,
        string $operation
    ): string {
        unset($defaultUrl);
        $this->assertSupportedOperation($operation);

        return OAuthConfig::codexApiBaseUrl() . '/' . ltrim($path, '/');
    }

    /**
     * {@inheritDoc}
     */
    public function prepareRequest(Request $request, string $operation): Request
    {
        $this->assertSupportedOperation($operation);

        if ($operation === OpenAiApiOperation::LIST_MODELS) {
            return $request->withData(['client_version' => '1.0.0']);
        }

        $params = $request->getData();
        if (!is_array($params)) {
            throw new RuntimeException(
                'The OpenAI account text request does not contain JSON parameters.'
            );
        }

        /*
         * The account-backed Codex endpoint requires streaming and does not
         * accept several public Responses API sampling parameters.
         */
        unset(
            $params['max_output_tokens'],
            $params['temperature'],
            $params['top_p']
        );
        $params['instructions'] = $params['instructions'] ?? 'You are a helpful assistant.';
        $params['store'] = false;
        $params['stream'] = true;

        if (!empty($params['tools']) && is_array($params['tools'])) {
            /** @var list<array<string, mixed>> $tools */
            $tools = $params['tools'];
            $params['tools'] = OpenAiCodexToolSchemaSanitizer::sanitize($tools);
            $params['tool_choice'] = 'auto';
            $params['parallel_tool_calls'] = true;
        }

        $requestOptions = $request->getOptions();
        if ($requestOptions === null || $requestOptions->getTimeout() === null) {
            $requestOptions = $requestOptions === null
                ? new RequestOptions()
                : clone $requestOptions;
            $requestOptions->setTimeout(120.0);
        }

        return $request
            ->withData($params)
            ->withHeader('Accept', 'text/event-stream')
            ->withOptions($requestOptions);
    }

    /**
     * {@inheritDoc}
     */
    public function normalizeResponse(Response $response, string $operation): Response
    {
        $this->assertSupportedOperation($operation);

        if ($operation === OpenAiApiOperation::GENERATE_TEXT) {
            return OpenAiCodexStreamResponseParser::parse($response);
        }

        return $response;
    }

    /**
     * {@inheritDoc}
     */
    public function parseModelMetadataList(Response $response): array
    {
        /** @var CodexModelsResponseData|null $responseData */
        $responseData = $response->getData();
        if (!isset($responseData['models']) || !is_array($responseData['models'])) {
            throw ResponseException::fromMissingData('OpenAI', 'models');
        }

        $capabilities = [
            CapabilityEnum::textGeneration(),
            CapabilityEnum::chatHistory(),
        ];
        $options = [
            new SupportedOption(OptionEnum::systemInstruction()),
            new SupportedOption(OptionEnum::maxTokens()),
            new SupportedOption(OptionEnum::temperature()),
            new SupportedOption(OptionEnum::topP()),
            new SupportedOption(OptionEnum::outputMimeType(), ['text/plain', 'application/json']),
            new SupportedOption(OptionEnum::outputSchema()),
            new SupportedOption(OptionEnum::functionDeclarations()),
            new SupportedOption(OptionEnum::webSearch()),
            new SupportedOption(OptionEnum::customOptions()),
            new SupportedOption(
                OptionEnum::inputModalities(),
                [
                    [ModalityEnum::text()],
                    [ModalityEnum::text(), ModalityEnum::image()],
                ]
            ),
            new SupportedOption(OptionEnum::outputModalities(), [[ModalityEnum::text()]]),
        ];

        /** @var list<array{metadata: ModelMetadata, priority: int}> $sortableModels */
        $sortableModels = [];
        foreach ($responseData['models'] as $modelData) {
            if (!is_array($modelData)) {
                continue;
            }

            $slug = $modelData['slug'] ?? null;
            if (!is_string($slug) || trim($slug) === '') {
                continue;
            }

            $visibility = $modelData['visibility'] ?? '';
            if (
                is_string($visibility)
                && in_array(strtolower(trim($visibility)), ['hide', 'hidden'], true)
            ) {
                continue;
            }

            $displayName = $modelData['display_name'] ?? $slug;
            if (!is_string($displayName) || trim($displayName) === '') {
                $displayName = $slug;
            }

            $priority = $modelData['priority'] ?? PHP_INT_MAX;
            if (!is_int($priority) && !is_float($priority)) {
                $priority = PHP_INT_MAX;
            }

            $sortableModels[] = [
                'metadata' => new ModelMetadata(
                    trim($slug),
                    trim($displayName),
                    $capabilities,
                    $options
                ),
                'priority' => (int) $priority,
            ];
        }

        usort(
            $sortableModels,
            static function (array $a, array $b): int {
                if ($a['priority'] === $b['priority']) {
                    return strcmp(
                        $a['metadata']->getId(),
                        $b['metadata']->getId()
                    );
                }

                return $a['priority'] <=> $b['priority'];
            }
        );

        return array_values(
            array_map(
                static function (array $model): ModelMetadata {
                    return $model['metadata'];
                },
                $sortableModels
            )
        );
    }

    /**
     * Ensures a caller cannot use the Codex endpoint for an unsupported operation.
     *
     * @param string $operation The requested operation.
     */
    private function assertSupportedOperation(string $operation): void
    {
        if ($this->supportsOperation($operation)) {
            return;
        }

        throw new RuntimeException(
            sprintf('The OpenAI account API profile does not support operation "%s".', $operation)
        );
    }
}
