<?php

declare(strict_types=1);

namespace Trikoder\Bundle\OAuth2Bundle\Manager\Doctrine;

use Doctrine\ORM\EntityManagerInterface;
use Lcobucci\Clock\Clock;
use Trikoder\Bundle\OAuth2Bundle\Manager\RefreshTokenManagerInterface;
use Trikoder\Bundle\OAuth2Bundle\Model\RefreshToken;

final class RefreshTokenManager implements RefreshTokenManagerInterface
{
    /**
     * @var EntityManagerInterface
     */
    private $entityManager;

    /**
     * @var Clock
     */
    private $clock;

    public function __construct(EntityManagerInterface $entityManager, Clock $clock)
    {
        $this->entityManager = $entityManager;
        $this->clock = $clock;
    }

    /**
     * {@inheritdoc}
     */
    public function find(string $identifier): ?RefreshToken
    {
        return $this->entityManager->find(RefreshToken::class, $identifier);
    }

    /**
     * {@inheritdoc}
     */
    public function save(RefreshToken $refreshToken): void
    {
        $this->entityManager->persist($refreshToken);
        $this->entityManager->flush();
    }

    public function clearExpired(): int
    {
        return $this->entityManager->createQueryBuilder()
            ->delete(RefreshToken::class, 'rt')
            ->where('rt.expiry < :expiry')
            ->setParameter('expiry', $this->clock->now())
            ->getQuery()
            ->execute();
    }

    public function clearRevoked(): int
    {
        return $this->entityManager->createQueryBuilder()
            ->delete(RefreshToken::class, 'rt')
            ->where('rt.revoked = true')
            ->getQuery()
            ->execute();
    }
}
