<?php

declare(strict_types=1);

namespace WordPress\OpenAiAiProvider\Authentication;

use WordPress\AiClient\Providers\Http\DTO\ApiKeyRequestAuthentication;
use WordPress\AiClient\Providers\Http\DTO\Request;

/**
 * Authenticates requests to the OAuth-backed OpenAI Codex endpoint.
 *
 * The PHP AI Client currently models API-key authentication only. Extending
 * that DTO keeps this provider compatible with the client registry while the
 * token manager supplies and refreshes the OAuth bearer token at request time.
 *
 * @since 1.1.0
 */
final class OpenAiOAuthRequestAuthentication extends ApiKeyRequestAuthentication
{
    /**
     * The token manager.
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
        /*
         * The placeholder is never sent. authenticateRequest() below obtains
         * a current access token immediately before every request.
         */
        parent::__construct('oauth-managed-token');
        $this->tokenManager = $tokenManager;
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
        $tokens = $this->tokenManager->getStoredTokenSet();
        if (!is_array($tokens)) {
            return 'oauth';
        }

        $accountId = $tokens['account_id'] ?? '';
        if (!is_string($accountId) || trim($accountId) === '') {
            return 'oauth';
        }

        return 'oauth_' . substr(hash('sha256', trim($accountId)), 0, 16);
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
