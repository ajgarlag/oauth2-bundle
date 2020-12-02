<?php

declare(strict_types=1);

namespace Trikoder\Bundle\OAuth2Bundle\Manager\InMemory;

use Lcobucci\Clock\Clock;
use Trikoder\Bundle\OAuth2Bundle\Manager\RefreshTokenManagerInterface;
use Trikoder\Bundle\OAuth2Bundle\Model\RefreshToken;

final class RefreshTokenManager implements RefreshTokenManagerInterface
{
    /**
     * @var RefreshToken[]
     */
    private $refreshTokens = [];

    /**
     * @var Clock
     */
    private $clock;

    public function __construct(Clock $clock)
    {
        $this->clock = $clock;
    }

    /**
     * {@inheritdoc}
     */
    public function find(string $identifier): ?RefreshToken
    {
        return $this->refreshTokens[$identifier] ?? null;
    }

    /**
     * {@inheritdoc}
     */
    public function save(RefreshToken $refreshToken): void
    {
        $this->refreshTokens[$refreshToken->getIdentifier()] = $refreshToken;
    }

    public function clearExpired(): int
    {
        $count = \count($this->refreshTokens);

        $now = $this->clock->now();
        $this->refreshTokens = array_filter($this->refreshTokens, static function (RefreshToken $refreshToken) use ($now): bool {
            return $refreshToken->getExpiry() >= $now;
        });

        return $count - \count($this->refreshTokens);
    }

    public function clearRevoked(): int
    {
        $count = \count($this->refreshTokens);

        $this->refreshTokens = array_filter($this->refreshTokens, static function (RefreshToken $refreshToken): bool {
            return !$refreshToken->isRevoked();
        });

        return $count - \count($this->refreshTokens);
    }
}
