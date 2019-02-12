<?php

namespace Trikoder\Bundle\OAuth2Bundle\Tests\Integration;

use DateTime;
use Trikoder\Bundle\OAuth2Bundle\Event\UserResolveEvent;
use Trikoder\Bundle\OAuth2Bundle\Model\AccessToken;
use Trikoder\Bundle\OAuth2Bundle\Model\RefreshToken;
use Trikoder\Bundle\OAuth2Bundle\Tests\Fixtures\FixtureFactory;
use Trikoder\Bundle\OAuth2Bundle\Tests\TestHelper;

final class AuthorizationServerTest extends AbstractIntegrationTest
{
    public function testSuccessfulAuthorizationThroughHeaders(): void
    {
        $request = $this->createAuthorizationRequest('foo:secret', [
            'grant_type' => 'client_credentials',
        ]);

        $response = $this->handleAuthorizationRequest($request);

        // Assert that we got something that looks like a normal response.
        $this->assertArrayHasKey('token_type', $response);
    }

    public function testSuccessfulAuthorizationThroughBody(): void
    {
        $request = $this->createAuthorizationRequest(null, [
            'client_id' => 'foo',
            'client_secret' => 'secret',
            'grant_type' => 'client_credentials',
        ]);

        $response = $this->handleAuthorizationRequest($request);

        // Assert that we got something that looks like a normal response.
        $this->assertArrayHasKey('token_type', $response);
    }

    public function testMissingAuthorizationCredentials(): void
    {
        $request = $this->createAuthorizationRequest(null, [
            'grant_type' => 'client_credentials',
        ]);

        $response = $this->handleAuthorizationRequest($request);

        // Response assertions.
        $this->assertSame('invalid_request', $response['error']);
        $this->assertSame('The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.', $response['message']);
        $this->assertSame('Check the `client_id` parameter', $response['hint']);
    }

    public function testInvalidAuthorizationCredentials(): void
    {
        $request = $this->createAuthorizationRequest('foo:wrong', [
            'grant_type' => 'client_credentials',
        ]);

        $response = $this->handleAuthorizationRequest($request);

        // Response assertions.
        $this->assertSame('invalid_client', $response['error']);
        $this->assertSame('Client authentication failed', $response['message']);
    }

    public function testMissingClient(): void
    {
        $request = $this->createAuthorizationRequest('yolo:wrong', [
            'grant_type' => 'client_credentials',
        ]);

        $response = $this->handleAuthorizationRequest($request);

        // Response assertions.
        $this->assertSame('invalid_client', $response['error']);
        $this->assertSame('Client authentication failed', $response['message']);
    }

    public function testInactiveClient(): void
    {
        $request = $this->createAuthorizationRequest('baz_inactive:woah', [
            'grant_type' => 'client_credentials',
        ]);

        $response = $this->handleAuthorizationRequest($request);

        // Response assertions.
        $this->assertSame('invalid_client', $response['error']);
        $this->assertSame('Client authentication failed', $response['message']);
    }

    public function testRestrictedGrantClient(): void
    {
        $request = $this->createAuthorizationRequest('qux_restricted:wicked', [
            'grant_type' => 'client_credentials',
        ]);

        $response = $this->handleAuthorizationRequest($request);

        // Response assertions.
        $this->assertSame('invalid_client', $response['error']);
        $this->assertSame('Client authentication failed', $response['message']);
    }

    public function testInvalidGrantType(): void
    {
        $request = $this->createAuthorizationRequest('foo:secret', [
            'grant_type' => 'non_existing',
        ]);

        $response = $this->handleAuthorizationRequest($request);

        // Response assertions.
        $this->assertSame('unsupported_grant_type', $response['error']);
        $this->assertSame('The authorization grant type is not supported by the authorization server.', $response['message']);
        $this->assertSame('Check that all required parameters have been provided', $response['hint']);
    }

    public function testInvalidScope(): void
    {
        $request = $this->createAuthorizationRequest('foo:secret', [
            'grant_type' => 'client_credentials',
            'scope' => 'non_existing',
        ]);

        $response = $this->handleAuthorizationRequest($request);

        // Response assertions.
        $this->assertSame('invalid_scope', $response['error']);
        $this->assertSame('The requested scope is invalid, unknown, or malformed', $response['message']);
        $this->assertSame('Check the `non_existing` scope', $response['hint']);
    }

    public function testValidClientCredentialsGrant(): void
    {
        $request = $this->createAuthorizationRequest('foo:secret', [
            'grant_type' => 'client_credentials',
        ]);

        timecop_freeze(new DateTime());

        $response = $this->handleAuthorizationRequest($request);

        timecop_return();

        $accessToken = $this->getAccessToken($response['access_token']);

        // Response assertions.
        $this->assertSame('Bearer', $response['token_type']);
        $this->assertSame(3600, $response['expires_in']);
        $this->assertInstanceOf(AccessToken::class, $accessToken);

        // Make sure the access token is issued for the given client ID.
        $this->assertSame('foo', $accessToken->getClient()->getIdentifier());
    }

    public function testValidClientCredentialsGrantWithScope(): void
    {
        $request = $this->createAuthorizationRequest('foo:secret', [
            'grant_type' => 'client_credentials',
            'scope' => 'fancy',
        ]);

        timecop_freeze(new DateTime());

        $response = $this->handleAuthorizationRequest($request);

        timecop_return();

        $accessToken = $this->getAccessToken($response['access_token']);

        // Response assertions.
        $this->assertSame('Bearer', $response['token_type']);
        $this->assertSame(3600, $response['expires_in']);
        $this->assertInstanceOf(AccessToken::class, $accessToken);

        // Make sure the access token is issued for the given client ID.
        $this->assertSame('foo', $accessToken->getClient()->getIdentifier());

        // The access token should have the requested scope.
        $this->assertEquals(
            [
                $this->scopeManager->find(FixtureFactory::FIXTURE_SCOPE_FIRST),
            ],
            $accessToken->getScopes()
        );
    }

    public function testValidPasswordGrant(): void
    {
        $this->eventDispatcher->addListener('trikoder.oauth2.user_resolve', function (UserResolveEvent $event) {
            $event->setUser(FixtureFactory::createUser());
        });

        $request = $this->createAuthorizationRequest('foo:secret', [
            'grant_type' => 'password',
            'username' => 'user',
            'password' => 'pass',
        ]);

        timecop_freeze(new DateTime());

        $response = $this->handleAuthorizationRequest($request);

        timecop_return();

        $accessToken = $this->getAccessToken($response['access_token']);
        $refreshToken = $this->getRefreshToken($response['refresh_token']);

        // Response assertions.
        $this->assertSame('Bearer', $response['token_type']);
        $this->assertSame(3600, $response['expires_in']);
        $this->assertInstanceOf(AccessToken::class, $accessToken);
        $this->assertInstanceOf(RefreshToken::class, $refreshToken);

        // Make sure refresh token belongs to the issued access token.
        $this->assertSame($accessToken, $refreshToken->getAccessToken());

        // The access token should be associated with the authenticated user.
        $this->assertSame('user', $accessToken->getUserIdentifier());
    }

    public function testInvalidCredentialsPasswordGrant(): void
    {
        $this->eventDispatcher->addListener('trikoder.oauth2.user_resolve', function (UserResolveEvent $event) {
            $event->setUser(null);
        });

        $request = $this->createAuthorizationRequest('foo:secret', [
            'grant_type' => 'password',
            'username' => 'user',
            'password' => 'pass',
        ]);

        $response = $this->handleAuthorizationRequest($request);

        // Response assertions.
        $this->assertSame('invalid_credentials', $response['error']);
        $this->assertSame('The user credentials were incorrect.', $response['message']);
    }

    public function testMissingUsernameFieldPasswordGrant(): void
    {
        $request = $this->createAuthorizationRequest('foo:secret', [
            'grant_type' => 'password',
            'password' => 'pass',
        ]);

        $response = $this->handleAuthorizationRequest($request);

        // Response assertions.
        $this->assertSame('invalid_request', $response['error']);
        $this->assertSame('The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.', $response['message']);
        $this->assertSame('Check the `username` parameter', $response['hint']);
    }

    public function testMissingPasswordFieldPasswordGrant(): void
    {
        $request = $this->createAuthorizationRequest('foo:secret', [
            'grant_type' => 'password',
            'username' => 'user',
        ]);

        $response = $this->handleAuthorizationRequest($request);

        // Response assertions.
        $this->assertSame('invalid_request', $response['error']);
        $this->assertSame('The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.', $response['message']);
        $this->assertSame('Check the `password` parameter', $response['hint']);
    }

    public function testValidRefreshGrant(): void
    {
        $existingRefreshToken = $this->refreshTokenManager->find(FixtureFactory::FIXUTRE_REFRESH_TOKEN);
        $existingAccessToken = $existingRefreshToken->getAccessToken();

        $request = $this->createAuthorizationRequest('foo:secret', [
            'grant_type' => 'refresh_token',
            'refresh_token' => TestHelper::generateEncryptedPayload($existingRefreshToken),
        ]);

        timecop_freeze(new DateTime());

        $response = $this->handleAuthorizationRequest($request);

        timecop_return();

        $accessToken = $this->getAccessToken($response['access_token']);
        $refreshToken = $this->getRefreshToken($response['refresh_token']);

        // Response assertions.
        $this->assertSame('Bearer', $response['token_type']);
        $this->assertSame(3600, $response['expires_in']);
        $this->assertInstanceOf(AccessToken::class, $accessToken);
        $this->assertInstanceOf(RefreshToken::class, $refreshToken);

        // Make sure old tokens are revoked.
        $this->assertTrue($existingRefreshToken->isRevoked());
        $this->assertTrue($existingAccessToken->isRevoked());

        // The newly issued tokens should be different.
        $this->assertNotSame($existingRefreshToken, $refreshToken);
        $this->assertNotSame($existingAccessToken, $accessToken);
    }

    public function testDifferentClientRefreshGrant(): void
    {
        $existingRefreshToken = $this->refreshTokenManager->find(FixtureFactory::FIXTURE_REFRESH_TOKEN_DIFFERENT_CLIENT);

        $request = $this->createAuthorizationRequest('foo:secret', [
            'grant_type' => 'refresh_token',
            'refresh_token' => TestHelper::generateEncryptedPayload($existingRefreshToken),
        ]);

        $response = $this->handleAuthorizationRequest($request);

        // Response assertions.
        $this->assertSame('invalid_request', $response['error']);
        $this->assertSame('The refresh token is invalid.', $response['message']);
        $this->assertSame('Token is not linked to client', $response['hint']);
    }

    public function testExpiredRefreshGrant(): void
    {
        $existingRefreshToken = $this->refreshTokenManager->find(FixtureFactory::FIXTURE_REFRESH_TOKEN_EXPIRED);

        $request = $this->createAuthorizationRequest('foo:secret', [
            'grant_type' => 'refresh_token',
            'refresh_token' => TestHelper::generateEncryptedPayload($existingRefreshToken),
        ]);

        $response = $this->handleAuthorizationRequest($request);

        // Response assertions.
        $this->assertSame('invalid_request', $response['error']);
        $this->assertSame('The refresh token is invalid.', $response['message']);
        $this->assertSame('Token has expired', $response['hint']);
    }

    public function testRevokedRefreshGrant(): void
    {
        $existingRefreshToken = $this->refreshTokenManager->find(FixtureFactory::FIXTURE_REFRESH_TOKEN_REVOKED);

        $request = $this->createAuthorizationRequest('foo:secret', [
            'grant_type' => 'refresh_token',
            'refresh_token' => TestHelper::generateEncryptedPayload($existingRefreshToken),
        ]);

        $response = $this->handleAuthorizationRequest($request);

        // Response assertions.
        $this->assertSame('invalid_request', $response['error']);
        $this->assertSame('The refresh token is invalid.', $response['message']);
        $this->assertSame('Token has been revoked', $response['hint']);
    }

    public function testMissingPayloadRefreshGrant(): void
    {
        $request = $this->createAuthorizationRequest('foo:secret', [
            'grant_type' => 'refresh_token',
        ]);

        $response = $this->handleAuthorizationRequest($request);

        // Response assertions.
        $this->assertSame('invalid_request', $response['error']);
        $this->assertSame('The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.', $response['message']);
        $this->assertSame('Check the `refresh_token` parameter', $response['hint']);
    }

    public function testInvalidPayloadRefreshGrant(): void
    {
        $request = $this->createAuthorizationRequest('foo:secret', [
            'grant_type' => 'refresh_token',
            'refresh_token' => 'invalid',
        ]);

        $response = $this->handleAuthorizationRequest($request);

        // Response assertions.
        $this->assertSame('invalid_request', $response['error']);
        $this->assertSame('The refresh token is invalid.', $response['message']);
        $this->assertSame('Cannot decrypt the refresh token', $response['hint']);
    }

    public function testSuccessfulCodeRequest(): void
    {
        $request = $this->createAuthorizeRequest(null, [
            'response_type' => 'code',
            'client_id' => 'foo',
        ]);

        $response = $this->handleAuthorizeRequest($request);

        // Response assertions.
        $this->assertArrayHasKey('code', $response);
    }

    public function testSuccessfulCodeRequestWithState(): void
    {
        $request = $this->createAuthorizeRequest(null, [
            'response_type' => 'code',
            'client_id' => 'foo',
            'state' => 'quzbaz',
        ]);

        $response = $this->handleAuthorizeRequest($request);

        // Response assertions.
        $this->assertArrayHasKey('code', $response);
        $this->assertSame('quzbaz', $response['state']);
    }

    public function testSuccessfulCodeRequestWithRedirectUri(): void
    {
        $request = $this->createAuthorizeRequest(null, [
            'response_type' => 'code',
            'client_id' => 'foo',
            'redirect_uri' => 'https://example.org/oauth2/redirect-uri',
        ]);

        $response = $this->handleAuthorizeRequest($request);

        // Response assertions.
        $this->assertArrayHasKey('code', $response);
    }

    public function testCodeRequestWithInvalidScope(): void
    {
        $request = $this->createAuthorizeRequest(null, [
            'response_type' => 'code',
            'client_id' => 'foo',
            'scope' => 'non_existing',
        ]);

        $response = $this->handleAuthorizeRequest($request);

        // Response assertions.
        $this->assertSame('invalid_scope', $response['error']);
        $this->assertSame('The requested scope is invalid, unknown, or malformed', $response['message']);
        $this->assertSame('Check the `non_existing` scope', $response['hint']);
    }

    public function testCodeRequestWithInvalidRedirectUri(): void
    {
        $request = $this->createAuthorizeRequest(null, [
            'response_type' => 'code',
            'client_id' => 'foo',
            'redirect_uri' => 'https://example.org/oauth2/other-uri',
        ]);

        $response = $this->handleAuthorizeRequest($request);

        // Response assertions.
        $this->assertSame('invalid_client', $response['error']);
        $this->assertSame('Client authentication failed', $response['message']);
    }

    public function testDeniedCodeRequest(): void
    {
        $request = $this->createAuthorizeRequest(null, [
            'response_type' => 'code',
            'client_id' => 'foo',
        ]);

        $response = $this->handleAuthorizeRequest($request, false);

        // Response assertions.
        $this->assertSame('access_denied', $response['error']);
        $this->assertSame('The resource owner or authorization server denied the request.', $response['message']);
        $this->assertSame('The user denied the request', $response['hint']);
    }

    public function testCodeRequestWithMissingClient(): void
    {
        $request = $this->createAuthorizeRequest(null, [
            'response_type' => 'code',
            'client_id' => 'yolo',
        ]);

        $response = $this->handleAuthorizeRequest($request, false);

        // Response assertions.
        $this->assertSame('invalid_client', $response['error']);
        $this->assertSame('Client authentication failed', $response['message']);
    }

    public function testCodeRequestWithInactiveClient(): void
    {
        $request = $this->createAuthorizeRequest(null, [
            'response_type' => 'code',
            'client_id' => 'baz_inactive',
        ]);

        $response = $this->handleAuthorizeRequest($request, false);

        // Response assertions.
        $this->assertSame('invalid_client', $response['error']);
        $this->assertSame('Client authentication failed', $response['message']);
    }

    public function testCodeRequestWithRestrictedGrantClient(): void
    {
        $request = $this->createAuthorizeRequest(null, [
            'response_type' => 'code',
            'client_id' => 'qux_restricted',
        ]);

        $response = $this->handleAuthorizeRequest($request, false);

        // Response assertions.
        $this->assertSame('invalid_client', $response['error']);
        $this->assertSame('Client authentication failed', $response['message']);
    }

    public function testSuccessfulAuthorizationWithCode(): void
    {
        $existingAuthCode = $this->authCodeManager->find(FixtureFactory::FIXTURE_AUTH_CODE);

        $request = $this->createAuthorizationRequest('foo:secret', [
            'grant_type' => 'authorization_code',
            'code' => TestHelper::generateEncryptedAuthCodePayload($existingAuthCode),
            'redirect_uri' => 'https://example.org/oauth2/redirect-uri',
        ]);

        $response = $this->handleAuthorizationRequest($request);
        $accessToken = $this->getAccessToken($response['access_token']);

        $this->assertSame('Bearer', $response['token_type']);
        $this->assertSame(3600, $response['expires_in']);
        $this->assertInstanceOf(AccessToken::class, $accessToken);
        $this->assertSame('foo', $accessToken->getClient()->getIdentifier());
    }

    public function testFailedAuthorizationWithCodeForOtherClient(): void
    {
        $existingAuthCode = $this->authCodeManager->find(FixtureFactory::FIXTURE_AUTH_CODE_DIFFERENT_CLIENT);

        $request = $this->createAuthorizationRequest('foo:secret', [
            'grant_type' => 'authorization_code',
            'code' => TestHelper::generateEncryptedAuthCodePayload($existingAuthCode),
            'redirect_uri' => 'https://example.org/oauth2/redirect-uri',
        ]);

        $response = $this->handleAuthorizationRequest($request);

        // Response assertions.
        $this->assertSame('invalid_request', $response['error']);
        $this->assertSame('The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.', $response['message']);
        $this->assertSame('Authorization code was not issued to this client', $response['hint']);
    }

    public function testFailedAuthorizationWithExpiredCode(): void
    {
        $existingAuthCode = $this->authCodeManager->find(FixtureFactory::FIXTURE_AUTH_CODE_EXPIRED);

        $request = $this->createAuthorizationRequest('foo:secret', [
            'grant_type' => 'authorization_code',
            'code' => TestHelper::generateEncryptedAuthCodePayload($existingAuthCode),
            'redirect_uri' => 'https://example.org/oauth2/redirect-uri',
        ]);

        $response = $this->handleAuthorizationRequest($request);

        // Response assertions.
        $this->assertSame('invalid_request', $response['error']);
        $this->assertSame('The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.', $response['message']);
        $this->assertSame('Authorization code has expired', $response['hint']);
    }

    public function testFailedAuthorizationWithInvalidRedirectUri(): void
    {
        $existingAuthCode = $this->authCodeManager->find(FixtureFactory::FIXTURE_AUTH_CODE);

        $request = $this->createAuthorizationRequest('foo:secret', [
            'grant_type' => 'authorization_code',
            'code' => TestHelper::generateEncryptedAuthCodePayload($existingAuthCode),
            'redirect_uri' => 'https://example.org/oauth2/other-uri',
        ]);

        $response = $this->handleAuthorizationRequest($request);

        // Response assertions.
        $this->assertSame('invalid_client', $response['error']);
        $this->assertSame('Client authentication failed', $response['message']);
    }

    public function testSuccessfulImplicitRequest(): void
    {
        $request = $this->createAuthorizeRequest(null, [
            'response_type' => 'token',
            'client_id' => 'foo',
        ]);

        $response = $this->handleAuthorizeRequest($request);
        $accessToken = $this->getAccessToken($response['access_token']);

        // Response assertions.
        $this->assertSame('Bearer', $response['token_type']);
        $this->assertEquals(600, $response['expires_in']);
        $this->assertInstanceOf(AccessToken::class, $accessToken);
        $this->assertSame('foo', $accessToken->getClient()->getIdentifier());
    }

    public function testSuccessfulImplicitRequestWithState(): void
    {
        $request = $this->createAuthorizeRequest(null, [
                'response_type' => 'token',
                'client_id' => 'foo',
                'state' => 'quzbaz',
            ]);

        $response = $this->handleAuthorizeRequest($request);
        $accessToken = $this->getAccessToken($response['access_token']);

        // Response assertions.
        $this->assertSame('Bearer', $response['token_type']);
        $this->assertEquals(600, $response['expires_in']);
        $this->assertInstanceOf(AccessToken::class, $accessToken);
        $this->assertSame('foo', $accessToken->getClient()->getIdentifier());
        $this->assertSame('quzbaz', $response['state']);
    }

    public function testSuccessfulImplicitRequestRedirectUri(): void
    {
        $request = $this->createAuthorizeRequest(null, [
                'response_type' => 'token',
                'client_id' => 'foo',
                'redirect_uri' => 'https://example.org/oauth2/redirect-uri',
            ]);

        $response = $this->handleAuthorizeRequest($request);
        $accessToken = $this->getAccessToken($response['access_token']);

        // Response assertions.
        $this->assertSame('Bearer', $response['token_type']);
        $this->assertEquals(600, $response['expires_in']);
        $this->assertInstanceOf(AccessToken::class, $accessToken);
        $this->assertSame('foo', $accessToken->getClient()->getIdentifier());
    }

    public function testImplicitRequestWithInvalidScope(): void
    {
        $request = $this->createAuthorizeRequest(null, [
                'response_type' => 'token',
                'client_id' => 'foo',
                'scope' => 'non_existing',
            ]);

        $response = $this->handleAuthorizeRequest($request);

        // Response assertions.
        $this->assertSame('invalid_scope', $response['error']);
        $this->assertSame('The requested scope is invalid, unknown, or malformed', $response['message']);
        $this->assertSame('Check the `non_existing` scope', $response['hint']);
    }

    public function testImplicitRequestWithInvalidRedirectUri(): void
    {
        $request = $this->createAuthorizeRequest(null, [
                'response_type' => 'token',
                'client_id' => 'foo',
                'redirect_uri' => 'https://example.org/oauth2/other-uri',
            ]);

        $response = $this->handleAuthorizeRequest($request);

        // Response assertions.
        $this->assertSame('invalid_client', $response['error']);
        $this->assertSame('Client authentication failed', $response['message']);
    }

    public function testDeniedImplicitRequest(): void
    {
        $request = $this->createAuthorizeRequest(null, [
                'response_type' => 'token',
                'client_id' => 'foo',
            ]);

        $response = $this->handleAuthorizeRequest($request, false);

        // Response assertions.
        $this->assertSame('access_denied', $response['error']);
        $this->assertSame('The resource owner or authorization server denied the request.', $response['message']);
        $this->assertSame('The user denied the request', $response['hint']);
    }

    public function testImplicitRequestWithMissingClient(): void
    {
        $request = $this->createAuthorizeRequest(null, [
                'response_type' => 'token',
                'client_id' => 'yolo',
            ]);

        $response = $this->handleAuthorizeRequest($request, false);

        // Response assertions.
        $this->assertSame('invalid_client', $response['error']);
        $this->assertSame('Client authentication failed', $response['message']);
    }

    public function testImplicitRequestWithInactiveClient(): void
    {
        $request = $this->createAuthorizeRequest(null, [
                'response_type' => 'token',
                'client_id' => 'baz_inactive',
            ]);

        $response = $this->handleAuthorizeRequest($request, false);

        // Response assertions.
        $this->assertSame('invalid_client', $response['error']);
        $this->assertSame('Client authentication failed', $response['message']);
    }

    public function testImplicitRequestWithRestrictedGrantClient(): void
    {
        $request = $this->createAuthorizeRequest(null, [
                'response_type' => 'token',
                'client_id' => 'qux_restricted',
            ]);

        $response = $this->handleAuthorizeRequest($request, false);

        // Response assertions.
        $this->assertSame('invalid_client', $response['error']);
        $this->assertSame('Client authentication failed', $response['message']);
    }
}
