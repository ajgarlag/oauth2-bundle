<?php

declare(strict_types=1);

namespace Trikoder\Bundle\OAuth2Bundle\Security\Authenticator;

use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResourceServer;
use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Trikoder\Bundle\OAuth2Bundle\Security\Authentication\Token\OAuth2Token;
use Trikoder\Bundle\OAuth2Bundle\Security\Authentication\Token\OAuth2TokenFactory;
use Trikoder\Bundle\OAuth2Bundle\Security\Exception\InsufficientScopesException;
use Trikoder\Bundle\OAuth2Bundle\Security\User\NullUser;

final class OAuth2Authenticator implements AuthenticationEntryPointInterface, AuthenticatorInterface
{
    private $httpMessageFactory;
    private $resourceServer;
    private $oauth2TokenFactory;
    private $userProvider;
    private $psr7Request;

    public function __construct(HttpMessageFactoryInterface $httpMessageFactory, ResourceServer $resourceServer, OAuth2TokenFactory $oauth2TokenFactory, UserProviderInterface $userProvider)
    {
        $this->httpMessageFactory = $httpMessageFactory;
        $this->resourceServer = $resourceServer;
        $this->oauth2TokenFactory = $oauth2TokenFactory;
        $this->userProvider = $userProvider;
    }

    public function start(Request $request, ?AuthenticationException $authException = null)
    {
        $exception = new UnauthorizedHttpException('Bearer');

        return new Response('', $exception->getStatusCode(), $exception->getHeaders());
    }

    public function supports(Request $request): ?bool
    {
        return 0 === strpos($request->headers->get('Authorization', ''), 'Bearer ');
    }

    public function authenticate(Request $request): PassportInterface
    {
        $psr7Request = $this->httpMessageFactory->createRequest($request);

        try {
            $this->psr7Request = $this->resourceServer->validateAuthenticatedRequest($psr7Request);
        } catch (OAuthServerException $e) {
            throw new AuthenticationException('The resource server rejected the request.', 0, $e);
        }

        $username = $this->psr7Request->getAttribute('oauth_user_id');

        $passport = new SelfValidatingPassport(new UserBadge($username, function ($username) {
            if ('' === $username) {
                return new NullUser();
            }
            $user = $this->userProvider->loadUserByUsername($username);
            if (!$user instanceof UserInterface) {
                throw new AuthenticationServiceException('The user provider must return a UserInterface object.');
            }

            return $user;
        }));

        return $passport;
    }

    public function createAuthenticatedToken(PassportInterface $passport, string $firewallName): TokenInterface
    {
        $passportUser = $passport instanceof UserPassportInterface ? $passport->getUser() : null;
        if ($passportUser instanceof NullUser) {
            $passportUser = null;
        }

        $oauth2Token = $this->oauth2TokenFactory->createOAuth2Token($this->psr7Request, $passportUser, $firewallName);

        if (!$this->isAccessToRouteGranted($oauth2Token)) {
            throw InsufficientScopesException::create($oauth2Token);
        }

        $oauth2Token->setAuthenticated(true);

        return $oauth2Token;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return $this->psr7Request = null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $this->psr7Request = null;

        throw $exception;
    }

    private function isAccessToRouteGranted(OAuth2Token $token): bool
    {
        $routeScopes = $this->psr7Request->getAttribute('oauth2_scopes', []);

        if ([] === $routeScopes) {
            return true;
        }

        $tokenScopes = $token
            ->getAttribute('server_request')
            ->getAttribute('oauth_scopes');

        /*
         * If the end result is empty that means that all route
         * scopes are available inside the issued token scopes.
         */
        return [] === array_diff($routeScopes, $tokenScopes);
    }
}
