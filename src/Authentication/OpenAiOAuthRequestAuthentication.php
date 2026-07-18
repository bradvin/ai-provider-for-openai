<?php

declare(strict_types=1);

namespace WordPress\OpenAiAiProvider\Authentication;

use WordPress\AiClient\Common\Exception\RuntimeException;
use WordPress\AiClient\Providers\Http\DTO\Request;
use WordPress\OpenAiAiProvider\Contracts\OpenAiApiProfileAwareAuthenticationInterface;
use WordPress\OpenAiAiProvider\Contracts\OpenAiApiProfileInterface;
use WordPress\OpenAiAiProvider\Profiles\OpenAiCodexApiProfile;

/**
 * Authenticates requests to the OAuth-backed OpenAI Codex endpoint.
 *
 * The token manager supplies and refreshes the OAuth bearer token at request
 * time, while the associated API profile adapts the public OpenAI request
 * dialect to the account-backed Codex endpoint.
 *
 * @since 1.1.0
 */
final class OpenAiOAuthRequestAuthentication implements OpenAiApiProfileAwareAuthenticationInterface
{
    /**
     * The token manager.
     *
     * @var OAuthTokenManager
     */
    private OAuthTokenManager $tokenManager;

    /**
     * The Codex API profile associated with this authentication.
     *
     * @var OpenAiCodexApiProfile
     */
    private OpenAiCodexApiProfile $apiProfile;

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
        $this->apiProfile = new OpenAiCodexApiProfile($tokenManager);
    }

    /**
     * {@inheritDoc}
     */
    public function getOpenAiApiProfile(): OpenAiApiProfileInterface
    {
        return $this->apiProfile;
    }

    /**
     * Adds the account bearer token and Codex routing headers to a request.
     *
     * @since 1.1.0
     *
     * @param Request $request The unauthenticated request.
     * @return Request The authenticated request.
     */
    public function authenticateRequest(Request $request): Request
    {
        if (!OAuthConfig::isAllowedCodexApiRequestUrl($request->getUri())) {
            throw new RuntimeException(
                'Refusing to send OpenAI account credentials outside the configured Codex API endpoint.'
            );
        }

        $accessToken = $this->tokenManager->getAccessToken();
        $request = $request
            ->withHeader('Authorization', 'Bearer ' . $accessToken)
            ->withHeader('originator', 'codex_cli_rs')
            ->withHeader(
                'User-Agent',
                'codex_cli_rs/0.0.0 (AI Provider for OpenAI; WordPress)'
            );

        $accountId = self::getChatGptAccountId($accessToken);
        if ($accountId !== null) {
            $request = $request->withHeader('ChatGPT-Account-ID', $accountId);
        }

        return $request;
    }

    /**
     * Gets a non-secret suffix for separating account model caches.
     *
     * @since 1.1.0
     *
     * @return string A stable cache suffix for the connected account.
     */
    public function getCacheKeySuffix(): string
    {
        return $this->apiProfile->getAccountCacheSuffix();
    }

    /**
     * Returns a token-free schema for managed account authentication.
     *
     * OAuth tokens are stored and refreshed internally. They must never be
     * serialized through the request authentication schema.
     *
     * @since 1.1.0
     *
     * @return array<string, mixed> The managed authentication schema.
     */
    public static function getJsonSchema(): array
    {
        return [
            'type' => 'object',
            'title' => 'OpenAI Account',
            'description' => 'Managed OpenAI account authentication.',
            'properties' => [],
            'additionalProperties' => false,
        ];
    }

    /**
     * Extracts the account routing claim from an access token.
     *
     * The token's signature is intentionally not verified here. The claim is
     * used only as a routing header and the token is still validated by OpenAI.
     *
     * @since 1.1.0
     *
     * @param string $accessToken The OAuth access token.
     * @return string|null The ChatGPT account ID, if present.
     */
    private static function getChatGptAccountId(string $accessToken): ?string
    {
        $parts = explode('.', $accessToken);
        if (count($parts) < 2) {
            return null;
        }

        $payload = strtr($parts[1], '-_', '+/');
        $remainder = strlen($payload) % 4;
        if ($remainder > 0) {
            $payload .= str_repeat('=', 4 - $remainder);
        }

        $decodedPayload = base64_decode($payload, true);
        if (!is_string($decodedPayload)) {
            return null;
        }

        $claims = json_decode($decodedPayload, true);
        if (!is_array($claims)) {
            return null;
        }

        $authClaims = $claims['https://api.openai.com/auth'] ?? null;
        if (!is_array($authClaims)) {
            return null;
        }

        $accountId = $authClaims['chatgpt_account_id'] ?? null;
        if (!is_string($accountId) || trim($accountId) === '') {
            return null;
        }

        return trim($accountId);
    }
}
